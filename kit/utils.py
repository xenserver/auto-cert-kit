# Copyright (c) Citrix Systems Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, 
# with or without modification, are permitted provided 
# that the following conditions are met:
#
# *   Redistributions of source code must retain the above 
#     copyright notice, this list of conditions and the 
#     following disclaimer.
# *   Redistributions in binary form must reproduce the above 
#     copyright notice, this list of conditions and the 
#     following disclaimer in the documentation and/or other 
#     materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND 
# CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, 
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR 
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, 
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, 
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING 
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
# SUCH DAMAGE.

"""A module for utility functions shared with multiple test cases"""
import logging
import logging.handlers
import subprocess
import datetime
import XenAPI
import sys
import time
import ssh
from xml.dom import minidom
import tarfile
import signal

import os
import base64
import threading

DROID_VM = 'droid_vm'
DEFAULT_PASSWORD = 'citrix'
FOR_CLEANUP = "for_cleanup"
DROID_VM_LOC = '/opt/xensource/packages/files/auto-cert-kit/vpx-dlvm.xva'
XE = '/opt/xensource/bin/xe'
DROID_TEMPLATE_TAG = "droid_vm_template"
REBOOT_ERROR_CODE = 3
HWOFFLOADS = ["rx", "tx", "sg", "tso", "ufo", "gso", "gro", "lro"]
REBOOT_FLAG_FILE = "/opt/xensource/packages/files/auto-cert-kit/reboot"

# Capability Tags
REQ_CAP = "REQ"

# XAPI States
XAPI_RUNNING_STATE = "Running"

class TestCaseError(Exception):
    """A subclassed exception object, which is raised by any
    test failure"""
    def __init__(self, *args):
        self.value = args[0]
        Exception.__init__(self, *args)
    def __str__(self):
        return repr("TEST_CASE_ERROR: %s" % self.value)

class TimeoutFunctionException(Exception):
    """Exception to raise on a timeout"""
    def __init__(self, *args):
        self.value = args[0]
        Exception.__init__(self, *args)
    def __str__(self):
        return repr("TIMEOUT_EXCEPTION: %s" % self.value)

class ArgumentError(Exception):
    """Raised when a user provides incomplete or missing arguments"""
    def __init__(self, *args):
        Exception.__init__(self, *args)

class ConfigFileNotFound(Exception):
    """Raised when a user provides incomplete or missing arguments"""
    def __init__(self, *args):
        self.file_name = args[0]
        self.config = args[1]
        Exception.__init__(self, *args)
    def __str__(self):
        return repr("%s file not found: '%s'. Please re-specify." % (self.config, self.file_name))


class InvalidArgument(ArgumentError):
    """Raised when a value provided as an argument is invalid"""
    def __init__(self, *args):
        self.arg_name = args[0]
        self.value = args[1]
        self.possibles = args[2]
    def __str__(self):
        return repr("INVALID_ARGUMENT: Argument Name: %s, Provided Value: '%s', Possible Options: %s" % (self.arg_name, self.value, self.possibles))

##### Exception Decorator
def log_exceptions(func):
    def decorated(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except XenAPI.Failure, e:
            log.error('%s: XenAPI.Failure: %s', func.__name__, str(e))
            raise
        except Exception, e:
            log.error('%s: %s: %s', func.__name__, e.__class__.__name__, str(e))
            raise
    return decorated
#############################

def int_to_bin(x):
    if x == 0:
        return ''
    else:
        return int_to_bin(x/2) + str(x%2)

class IPv4Addr(object):
    """Class for storing information about IP address"""

    def __init__(self, ip, netmask, gateway):
        self.addr = ip
        self.netmask = netmask
        self.gateway = gateway
        self.validate_ip()
        self.validate_netmask()

    def validate_ip(self):
        arr = self.addr.split('.')
        if len(arr) != 4:
            raise Exception("Error: IP address is not correct: '%s'" % 
                            self.addr)

        for i in range(0,4):
            if int(arr[i]) > 255:
                raise Exception("IP address is out of range: %s" % self.addr)

    def validate_netmask(self):
        arr = self.netmask.split('.')

        # Extract netmask into a single mask
        mask_str = ""
        for group in arr:
            mask_str = mask_str + int_to_bin(int(group))[2:]

        # For a netmask, we expect a contigious line of ones.
        zero_pos = mask_str.find('0')
        
        if zero_pos == -1:
            return True
        else:
            if '1' in mask_str[zero_pos + 1:]:
                raise Exception("Invalid netmask: '%s' ('%s')" % (self.netmask, mask_str))

    def to_bin(self, integer):
        """Convert an integer to a 8bit string"""
        if integer > 256:
            raise Exception("'to_bin' method is only for 8bit integers")

        bin_str = int_to_bin(integer)[2:]
        
        tmp_str = ""
        for i in range(8 - len(bin_str)):
            tmp_str = tmp_str + "0"

        return tmp_str + bin_str

    def byte_mask_match(self, bina, binb, mask):
        """For two 8bit binary strings, check that they match for
        any masked bits"""

        for i in range(8):
            if mask[i] == '1':
                if bina[i] != binb[i]:
                    return False
            elif mask[i] == '0':
                continue
            else:
                raise Exception("Unexpected characted '%s' in binary string." % mask[i])

        return True

    def on_subnet(self, ip):
        # Check that mask is the same
        if self.netmask != ip.netmask:
            return False

        # Mask both IPs and check whether they are equal.
        arrA = self.addr.split('.')
        arrB = ip.addr.split('.')
        arrMask = self.netmask.split('.')

        for i in range(0, 4):
            a = self.to_bin(int(arrA[i]))
            b = self.to_bin(int(arrB[i]))
            m = self.to_bin(int(arrMask[i]))

            if not self.byte_mask_match(a, b, m):
                return False
        return True        
            
            
class StaticIPManager(object):
    """Class for managing static IP address provided by
    the caller. Allows us to do simple 'leasing' operations"""

    free = []
    in_use = []
    
    def __init__(self, conf):
        # Populate the internal list of IPs
        free = []
        for ip_addr in self.generate_ip_list(conf['ip_start'], 
                                        conf['ip_end']):
            free.append(IPv4Addr(ip_addr,
                                 conf['netmask'],
                                 conf['gw']))

        self.free = free

    def generate_ip_list(self, ip_start, ip_end):
        """Take an IP address start, and end, and compose a list of all 
        the IP addresses inbetween. E.g. '192.168.0.1' - '192.168.0.4' would
        return ['192.168.0.1', '192.168.0.2', '192.168.0.3', '192.168.0.4']."""

        def validate_ip(str_ip):
            try:
                arr = str_ip.split('.')
                res = []
                for i in range(0,4):
                    res.append(int(arr[i]))
                    if res[i] > 254:
                        raise Exception("Invalid IP %s" % str_ip)
                return arr
            except Exception, e:
                raise Exception("Error: '%s' is not a valid IPv4 Addr (%s)" % (str_ip,str(e)))

        arr1 = validate_ip(ip_start)
        arr2 = validate_ip(ip_end)

        for i in range(4):
            if int(arr2[i]) < int(arr1[i]):
                raise Exception("IP start ('%s') must be smaller than IP end ('%s') (%s <  %s)" %
                                (ip_start,
                                ip_end, arr2[i], arr1[i]))
        
        res = []

        res.append(ip_start)

        if ip_end == ip_start:
            return res

        tmp_string = self.increment_ip_string(ip_start)

        while tmp_string != ip_end:
            res.append(tmp_string)
            tmp_string = self.increment_ip_string(tmp_string)

        # After exit, we must also add the last value
        res.append(ip_end)
            
        return res
        
    def increment_ip_string(self, string):
        chars = string.split('.')
        arr = []
        for i in range(4):
            arr.append(int(chars[i]))

        def carry(x):
            if int(x) == 254:
                return True
            else:
                return False

        if not carry(arr[3]):
            arr[3] = arr[3] + 1
        elif not carry(arr[2]):
            arr[3] = 1
            arr[2] = arr[2] + 1
        elif not carry(arr[1]):
            arr[3] = 1
            arr[2] = 1
            arr[1] = arr[1] + 1
        elif not carry(arr[0]):
            arr[3] = 1
            arr[2] = 1
            arr[1] = 1
            arr[0] = arr[0] + 1

        if arr[0] == 255:
            raise Exception("Error: Invalid to increment: %s" % string)

        return "%s.%s.%s.%s" % (arr[0],arr[1],arr[2],arr[3])


    def get_ip(self):
        """Return an unused IP object (if one exists)"""
        if self.free:
            free_list = list(self.free)
            in_use_list = list(self.in_use)
            ip = free_list.pop()
            in_use_list.append(ip)
            self.free = free_list
            self.in_use = in_use_list
            return ip
        else:
            raise Exception("Error: no more IP addresses to allocate! (%d in use)" %
                            len(self.in_use))
                
    def return_ip(self, ip):
        """For a given IP object, attempt to remove from the 'in_use' list, and put
        it back into circulation for others to use"""
        try:
            in_use = list(self.in_use)
            free = list(self.free)
            
            in_use.remove(ip)
            free.append(ip)

            self.in_use = list(in_use)
            self.free = list(free)
            
        except ValueError, e:
            log.debug("Exception: %s" % str(e))
            raise Exception("Trying to return an IP address that did not orginally exist!")

    def release_all(self):
        """Return all of the IP addresses that are currently in use"""
        in_use = list(self.in_use)
        free = list(self.free)
        for item in in_use:
            free.append(item)

        self.in_use = []
        self.free = free

class IfaceStats(object):
    """Class object for representing network statistics associated
       with an ethernet interface"""

    # List of keys depended on by callers
    required_keys = ['rx_bytes', 'tx_bytes']

    def __init__(self,iface, rec):
        setattr(self, 'iface', iface)
        self.validate_args(rec)
       
        # Load all key/values into the class as attributes 
        for k,v in rec.iteritems():
            setattr(self, k, int(v))

    def validate_args(self, rec):
        for key in self.required_keys:
            if key not in rec.keys():
                raise Exception("Error: could not find key '%s'" % key + \
                                " in iface statistics record '%s'" % rec) 
                                                           

##### Logging setup

log = None
def configure_logging(name):
    """Method for configuring Logging"""
    global log
    if not log:
        log = logging.getLogger(name)
        log.setLevel(logging.DEBUG)
        fileh = logging.FileHandler('/var/log/auto-cert-kit.log')
        fileh.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%%(asctime)-8s %s: %%(levelname)-8s %%(filename)s:%%(lineno)-10d %%(message)s' % name)
        fileh.setFormatter(formatter)
        log.addHandler(fileh)
        log.debug("Added fileh")
        sth = logging.StreamHandler(sys.__stdout__)
        sth.setLevel(logging.DEBUG)
        log.debug("Adding sth")
        log.addHandler(sth)
    return log

if not log:
    log = configure_logging('auto-cert-kit')

def get_logger(name):
    """Method to return instance of logger"""
    return logging.getLogger(name)

def get_local_xapi_session():
    """Login to Xapi locally. This will only work if this script is being run 
    on Dom0. For this, no credentials are required."""
    session = XenAPI.xapi_local()
    session.login_with_password("", "")
    return session

def get_remote_xapi_session(creds):
    """Return a remote xapi session based on creds"""
    session = XenAPI.Session("http://%s" % creds['host'])
    session.login_with_password(creds['user'], creds['pass'])
    return session

def get_pool_master(session):
    """Returns the reference to host which is currently master
    over the pool which can be seen with the given session"""
    pool_ref = session.xenapi.pool.get_all()[0]
    host_ref = session.xenapi.pool.get_master(pool_ref)
    return host_ref

def _find_control_domain(session, host_ref):
    vm_recs = session.xenapi.VM.get_all_records()
    for vm_ref, vm_rec in vm_recs.iteritems():
        if vm_rec['is_control_domain'] and vm_rec['resident_on'] == host_ref:
            return vm_ref
    raise Exception("Unexpected error. Cannot find control domain on host %s" % host_ref)

def get_master_control_domain(session):
    master_ref = get_pool_master(session)
    return _find_control_domain(session, master_ref)

def get_slave_control_domain(session):
    slave_refs = get_pool_slaves(session)
    if not slave_refs:
        raise Exception("Error: the test kit requires a pool of at least 2 hosts.")
    #Only care about the first slave reference
    return _find_control_domain(session, slave_refs[0])

def set_reboot_flag():
    """Set an OS flag (i.e. touch a file) for when we're about to reboot.
    This is so that, on host reboot, we can work out whether we should
    run, and what the status of the kit is"""
    open(REBOOT_FLAG_FILE, 'w').close()

def get_reboot_flag():
    if os.path.exists(REBOOT_FLAG_FILE):
        return True
    else:
        return False

def clear_reboot_flag():
    if os.path.exists(REBOOT_FLAG_FILE):
        os.remove(REBOOT_FLAG_FILE)
            
def host_reboot(session):
    log.debug("Attempting to reboot the host")
    #Cleanup all the running vms
    pool_wide_cleanup(session)

    master = get_pool_master(session)
    
    hosts = session.xenapi.host.get_all()
    for host in hosts:
        session.xenapi.host.disable(host)
        if host != master:
            session.xenapi.host.reboot(host)
            
    set_reboot_flag()

    session.xenapi.host.reboot(master)
    log.debug("Rebooted master")
    sys.exit(REBOOT_ERROR_CODE)
    

def print_test_results(tracker):
    """Method for pretty printing results"""
    for mlist in tracker:
        for testclass in mlist:
            for test in testclass:
                print "****Test Name:", test['test_name'], "****"
                print "Test Result:", test['result']
                if test.has_key('info'):
                    print "Additional Info:", test['info']
                if test.has_key('data'):
                    print "Data:", test['data']
                if test.has_key('config'):
                    print "Config:", test['config']
                if test.has_key('exception'):
                    print "Exceptions:", test['exception'], "\n"
                else:
                    print 

def get_pool_slaves(session):
    """Returns a list of references for each host in a pool
    which is not a pool master"""
    slaves = []
    hosts = session.xenapi.host.get_all()
    master_ref = get_pool_master(session)
    for host in hosts:
        if master_ref != host:
            slaves.append(host)
    return slaves

def get_xenserver_version(session):
    """Return the XenServer version (using the master host)"""
    master_ref = get_pool_master(session)
    software = session.xenapi.host.get_software_version(master_ref)
    xs_str = software['xs:main']
    #parse string of the form: 'XenServer Pack, version 6.0.0, build 50762c'
    arr = xs_str.split(',')
    for item in arr:
        if item.strip().startswith('version'):
            version = item.strip().split(' ')[1]
            return version
    raise Exception("XenServer Version could not be detected! %s" % xs_str)

def eval_expr(expr, val):
    """Evaluate an expression against a provided value.
    Expressions should be in the form '<condition> <value>'"""
    log.debug("Eval Expr: %s %s" % (expr, val))
    arr = expr.split()
    if len(arr) > 3:
        raise Exception("Could not evaluate expression. " + 
                        "Format is incorrect: %s" % expr)

    condition = arr[0]
    test_val = ' '.join(arr[1:])

    if condition == ">":
        return val > test_val
    if condition == "<":
        return val < test_val
    if condition == "=":
        return val == test_val
    if condition == "!=":
        return val != test_val
    if condition == ">=":
        return val >= test_val
    if condition == "<=":
        return val <= test_val

    raise Exception("Specified condition is not yet supported for comparison: %s" % 
                    condition)

def append_result_node(dom, parent_node, result):
    """parent_node is an xml node to be appended to, result
    is a dictionary item"""
    element = dom.createElement("test")
    parent_node.appendChild(element)
    for key in result.keys():
        k = dom.createElement(key)
        element.appendChild(k)
        k.appendChild(dom.createTextNode(result[key]))

def make_local_call(call):
    """Function wrapper for making a simple call to shell"""
    log.debug(' '.join(call))
    process = subprocess.Popen(call, stdout=subprocess.PIPE)
    stdout, stderr = process.communicate()
    if process.returncode == 0:
        print stdout
        return str(stdout).strip()
    else:
        log.debug("ERR: %s, %s" % (stdout, stderr))
        sys.exit()

def save_bugtool():
    """Saves a bugtool and returns the name"""
    print "Collecting a bugtool report:"
    call = ["xen-bugtool", "--yestoall"]
    info = make_local_call(call)
    where = info.find('/var/opt/xen/bug-report')
    return ((info[where:]).split())[0]

def compress_output_files(mylist):
    """Compress all output files to bz2 and return the name"""
    print "Compressing output files..."""
    tar = tarfile.open("auto-cert-kit-logs.tar.bz2", "w:bz2")
    for myfile in mylist:
        tar.add(myfile)
    tar.close()

def output_test_results(tracker):
    """Outputs an xml results doc and creates a xen-bugtool,
    then bzip2 them together"""
    xml_file_name = ('cert_log_%s.xml' % datetime.datetime.now())
    myfile = open(xml_file_name, 'w')
    doc = xml.dom.minidom.Document()
    top_element = doc.createElement("results")
    doc.appendChild(top_element)
    for all_results in tracker:
        for test_class in all_results:
            for test_result in test_class:
                append_result_node(doc, top_element, test_result)
    myfile.write(doc.toprettyxml())
    myfile.close()
    bugtool = save_bugtool()
    compress_output_files([xml_file_name, bugtool])
                       
def create_network(session, name_label, description, other_config):
    """Method for creating a XAPI network"""
    net_ref = session.xenapi.network.create({'name_label':name_label,
                                   'description':description,
                                   'other_config':other_config})
    oc = session.xenapi.network.get_other_config(net_ref)
    oc[FOR_CLEANUP] = "true"
    session.xenapi.network.set_other_config(net_ref, oc)
    return net_ref

def create_nic_bond(session, network, nics, mac='', mode='balance-slb'):
    """Creates a bond of type mode between two PIFs and returns 
    the network reference"""
    if len(nics) != 2:
        raise Exception("Expected two PIFs, received %s" % len(nics))
    log.debug("About to create bond between PIFs %s in mode %s" % (nics, mode))
    net_ref = session.xenapi.Bond.create(network, nics, mac, mode)
    oc = session.xenapi.Bond.get_other_config(net_ref)
    oc[FOR_CLEANUP] = "true"
    session.xenapi.Bond.set_other_config(net_ref, oc)
    return net_ref

def get_pifs_by_device(session, device, hosts=[]):
    """Using device name (e.g. eth0) return a reference to the PIF that 
    is plugged into the master"""
    if hosts == []:
        hosts = session.xenapi.host.get_all()
    pifs = []
    for host in hosts:
        pifs = pifs + session.xenapi.host.get_PIFs(host)
    results = []
    for pif in pifs:
        if session.xenapi.PIF.get_physical(pif) \
                and (session.xenapi.PIF.get_device(pif) == device):
            results.append(pif)

    if len(results) > 0:
        return results
    raise TestCaseError("""No Ethernet device named %s 
                        can be found on host(s) %s""" % 
                        (device, hosts))

def filter_pif_devices(session, devices):
    """Return non management devices from the set of devices
    defined by a user."""
    res = []
    management_device = get_pool_management_device(session)
    
    for device in devices:
        if device != management_device:
            res.append(device)

    if not res:
        raise TestCaseError("""Couldn't find a non-manamgement 
                                interfaces from those supplied""")
    return res

def get_equivalent_devices(session, device):
    devices = get_master_network_devices(session)
    ifaces = [dev['Kernel_name'] for dev in devices if device['PCI_id'] == dev['PCI_id']]
    log.debug("Equivalent devices for %s: %s" % (device, ifaces))
    return ifaces

def get_management_network(session):
    networks = session.xenapi.network.get_all()
    for network in networks:
        pifs = session.xenapi.network.get_PIFs(network)
        for pif in pifs:
            if session.xenapi.PIF.get_management(pif):
                return network

    raise Exception("ERROR: No management network found!")

def create_vlan(session, pif_ref, network_ref, vlan_id):
    """Create a VLAN PIF from an existing physical PIF on the specified
    network"""
    log.debug("About to create_vlan")
    return session.xenapi.VLAN.create(pif_ref, str(vlan_id), network_ref)

def get_droid_templates(session, brand=DROID_TEMPLATE_TAG):
    """Return the reference to the template for the 
    demo linux VM. This is obtained by searching for 
    a template with the other_config key 'droid_template_vm'."""
    vms = session.xenapi.VM.get_all()
    droid_vms = []
    for vm in vms:
        if brand in session.xenapi.VM.get_other_config(vm):
            droid_vms.append(vm)
    return droid_vms

def brand_vm(session, vm_ref, brand=DROID_VM):
    """Take a VM, or template and brand it with a key in other_config"""
    oc = session.xenapi.VM.get_other_config(vm_ref)
    oc[brand] = 'True'
    session.xenapi.VM.set_other_config(vm_ref, oc)

def convert_to_template(session, vm_ref):
    """Convert a VM to a template"""
    return session.xenapi.VM.set_is_a_template(vm_ref, True)

def create_vif(session, device, network, vm, mac=''):
    """Method for creating a XAPI Virtual Interface"""
    return session.xenapi.VIF.create({'device': device,
                               'network': network,
                               'VM': vm,
                               'MAC': mac,
                               'MTU': '1504',
                               'other_config': {},
                               'qos_algorithm_type': '',
                               'qos_algorithm_params': {}})

def setup_vm_on_network(session, vm_ref, network_ref, iface='eth0', wipe=True):
    """Remove VIFs plugged into a VM, and create a new
    VIF and plug it in for a particular network"""
    
    if wipe:
        #1. Remove all existings VIFs
        vif_refs = session.xenapi.VM.get_VIFs(vm_ref)
        log.debug("Existing VIFs %s" % vif_refs)

        for vif_ref in vif_refs:
            log.debug("Unplug and destroy VIF %s" % vif_ref)

            if session.xenapi.VM.get_power_state(vm_ref) == "Running":
                log.debug("Unplugging VIF... %s" % vif_ref)
                session.xenapi.VIF.unplug(vif_ref)
            log.debug("Destroing VIF... %s" % vif_ref)
            session.xenapi.VIF.destroy(vif_ref)

    log.debug("Create a new VIF for VM")
    log.debug("Network ref = %s" % network_ref)
    #2. Create a new VIF attached to the specified network reference
    vif_ref = create_vif(session, iface.replace('eth',''), network_ref, vm_ref)
    
    if session.xenapi.VM.get_power_state(vm_ref) == "Running":
        log.debug("Plug VIF %s" % vif_ref)
        session.xenapi.VIF.plug(vif_ref)

    return vif_ref
   

def make_vm_noninteractive(session, vm_ref):
    """Set PV args to ensure the Demo VM boots up automatically,
    without requring a user to add a password"""
    session.xenapi.VM.set_PV_args(vm_ref, 'noninteractive')

def xenstore_read(path):
    """Uses the local xenstore utility to read a specified path"""
    process = subprocess.Popen(['/usr/bin/xenstore-read', path],
                               stdout=subprocess.PIPE)
    stdout, stderr = process.communicate()
    if process.returncode == 0:
        return stdout
    else:
        raise TestCaseError(stderr)

def should_timeout(start, timeout):
    """Method for evaluating whether a time limit has been met"""
    return time.time() - start > float(timeout)

def _get_control_domain_ip(session, vm_ref, device='xenbr0'):
    """Return the IP address for a specified control domain"""
    if not session.xenapi.VM.get_is_control_domain(vm_ref):
        raise Exception("Specified VM is not a control domain")

    host_ref = session.xenapi.VM.get_resident_on(vm_ref)

    return session.xenapi.host.call_plugin(host_ref, 
                                          'autocertkit',
                                          'get_local_device_ip', 
                                           {'device': device}
                                           ) 

def wait_for_ip(session, vm_ref, device, timeout=300):
    """Wait for an IP address to be returned (until a given timeout)"""

    # Check to see if a static IP has been configured
    xs_data = session.xenapi.VM.get_xenstore_data(vm_ref)
    log.debug("xenstore data: %s" % xs_data)
    key = 'vm-data/control/%s/ip' % device
    if key in xs_data.keys():
        log.debug("Static IP %s found for VM %s" % (xs_data[key], vm_ref))
        return xs_data[key]

    if session.xenapi.VM.get_is_control_domain(vm_ref):
        ipaddr = _get_control_domain_ip(session, vm_ref, device)
        log.debug("Control domain %s has IP %s on device %s" % (vm_ref, ipaddr, device))
        return ipaddr

    if not device.startswith('eth'):
        raise Exception("Invalid device specified, it should be in the format 'ethX'")

    start = time.time()

    def should_timeout(start, timeout):
        """Method for evaluating whether a time limit has been met"""
        return time.time() - start > float(timeout)

    i = 0
    while not should_timeout(start, timeout):
        log.debug("Trying to retrieve VM IP address - Attempt %d" % i)
        ips = get_vm_ips(session, vm_ref)
        log.debug("VM %s has these %s IPs" % (vm_ref, ips))

        for k, v in ips.iteritems():
            if k == device:
                return v

        i = i + 1
        time.sleep(5)

    raise Exception("""Timeout has been exceeded waiting for IP
                     address of VM to be returned %s """ % str(timeout))

def get_vm_ips(session, vm_ref):
    guest_metrics_ref = session.xenapi.VM.get_guest_metrics(vm_ref)
    if guest_metrics_ref == "OpaqueRef:NULL":
        return {} 
    networks = session.xenapi.VM_guest_metrics.get_networks(guest_metrics_ref)
    res = {}
    for k, v in networks.iteritems():
        if k.endswith('ip'):
            res["eth%s" % (k.replace('/ip', ''))] = v
    return res
    

def ping(vm_ip, dst_vm_ip, interface, packet_size=1400,
         count=20, username="root", password=DEFAULT_PASSWORD):
    """Function for executing ping instruction via SSH to vm_ip.
    The ping command is then set against the interface specified,
    and directed at the dst_vm_ip given. If the packet is larger
    than the default, also run MTU discovery"""

    if packet_size > 1400:
        cmd_str = "ping -I %s -s %d -c %d -M do %s" % \
            (interface, packet_size, count, dst_vm_ip)
    else:
        cmd_str = "ping -I %s -s %d -c %d %s" % \
            (interface, packet_size, count, dst_vm_ip)
    log.debug("Ping: %s" % cmd_str)
    result = ssh_command(vm_ip, username, password, cmd_str, attempts=10).split('\n')
    log.debug("Results= %s" % result)
    for line in result:
        log.debug("SSH Line: %s" % line)
        if 'transmitted' in line:
            return line
    raise TestCaseError("""Error: Unexpected response 
                       from ping, to transmission statistics: %s""" \
                            % result)


def ssh_command(ip, username, password, cmd_str, dbg_str=None, attempts=10):
    """execute an SSH command using the parimiko library, in order
    to specify a password. Return the result to the caller."""
    if dbg_str:
        log.debug(dbg_str)

    for i in range(0, attempts):
        log.debug("Attempt %d/%d: %s" % (i, attempts, cmd_str))

        try:
            cmd = ssh.SSHCommand(ip, cmd_str, log, username, 900, password)
            return cmd.read("string").strip()
        except Exception, e:
            log.debug("Exception: %s" % str(e))
            if i + 1 == attempts:
                # If we have reached our attempts limit, and still have
                # raised an exception, we should elevate the exception.
                log.debug("Max attempt reached %d/%d" % (i + 1, attempts))
                raise e
            # Sleep before next attempt
            time.sleep(20)

    raise Exception("An unkown error has occured!")


def add_network_interface(vm_ip, interface_name, interface_ip,
                          interface_netmask, username="root",
                          password=DEFAULT_PASSWORD, dhcp=False):
    """Configures a network interface inside a linux VM"""
    log.debug("add_network_interface for %s" % vm_ip)
    if dhcp:
        cmd = "ifconfig %s up" % interface_name
    else:
        cmd = "ifconfig %s %s netmask %s up" % \
            (interface_name, interface_ip, interface_netmask)

    ssh_command(vm_ip, username, password, cmd, cmd, attempts=10)    
		

def destroy_vm(session, vm_ref, timeout=60):
    """Checks powerstate of a VM, destroys associated VDIs, 
    and destroys VM once shutdown"""
    #Check if the VM is either running or booting. The VM will fail to shutdown if it is booting, so wait.
    if (session.xenapi.VM.get_power_state(vm_ref) == "Running") or (session.xenapi.VM.get_allowed_operations(vm_ref) == []):
        start = time.time()
        ops_list = session.xenapi.VM.get_allowed_operations(vm_ref)
        while 'hard_shutdown' not in ops_list:
            time.sleep(1)
            log.debug("VM shutdown not allowed, waiting for VM %s to boot" % vm_ref)
            ops_list = session.xenapi.VM.get_allowed_operations(vm_ref)
            if should_timeout(start, timeout):
                raise Exception("Bad VM power state: VM %s did not transition to 'running'" % vm_ref)
        #Once the VM reports hard_shutdown as an allowed_op, shutdown the VM
        session.xenapi.VM.hard_shutdown(vm_ref)
    #Check that the VDI is not in-use
    vbd_refs = session.xenapi.VM.get_VBDs(vm_ref)
    for vbd_ref in vbd_refs:
        vdi_ref = session.xenapi.VBD.get_VDI(vbd_ref)
        log.debug("Destroying VDI %s" % vdi_ref)
        try:
            start = time.time()
            ops_list = session.xenapi.VDI.get_allowed_operations(vdi_ref)
            while 'destroy' not in ops_list:
                time.sleep(1)
                ops_list = session.xenapi.VDI.get_allowed_operations(vdi_ref)
                if should_timeout(start, timeout):
                    raise Exception("Cannot destroy VDI: VDI is still active")
            #If the VDI is free, try to destroy it. Should pass the exception catch if it is a NULL VDI reference.
            session.xenapi.VDI.destroy(vdi_ref)
        except XenAPI.Failure, exn:
            if exn.details[0] == 'HANDLE_INVALID':
                pass
            else:
                raise exn
    #Finally, destroy the VM
    log.debug("Destroying VM %s" % vm_ref)
    session.xenapi.VM.destroy(vm_ref)

def pool_wide_cleanup(session, tag=FOR_CLEANUP):
    """This function will look for all the object with a given tag,
    and remove them as part of a cleanup operation"""
    log.debug("**Performing pool wide cleanup...**")
    pool_wide_vm_cleanup(session, tag)
    pool_wide_network_cleanup(session, tag)


def pool_wide_vm_cleanup(session, tag):
    """Searches for VMs with a cleanup tag, and destroys"""
    vms = session.xenapi.VM.get_all()
    for vm in vms:
        oc = session.xenapi.VM.get_other_config(vm)
        if tag in oc:
            destroy_vm(session, vm)
            continue

        if session.xenapi.VM.get_is_control_domain(vm):
            # Cleanup any routes that are lying around
            keys_to_clean = []
            for k, v in oc.iteritems():
                if k.startswith('route_clean_'):
                    # Call plugin
                    call_ack_plugin(session, 'remove_route',
                                    {
                                        'vm_ref': vm,
                                        'dest_ip': v,
                                    })
                    keys_to_clean.append(k)
            
            if keys_to_clean:
                for key in keys_to_clean:
                    del oc[key]

                session.xenapi.VM.set_other_config(vm, oc)


def pool_wide_network_cleanup(session, tag):
    """Searches for networks with a cleanup tag, and
    destroys if found"""
    bonds = session.xenapi.Bond.get_all()
    for bond in bonds:
        if tag in session.xenapi.Bond.get_other_config(bond):
            session.xenapi.Bond.destroy(bond)
    networks = session.xenapi.network.get_all()
    for network in networks:
        if tag in session.xenapi.network.get_other_config(network):
            pifs = session.xenapi.network.get_PIFs(network)
            log.debug("Pifs to cleanup: %s" % pifs)
            for pif in pifs:
                session.xenapi.PIF.unplug(pif)
                session.xenapi.PIF.destroy(pif)
            session.xenapi.network.destroy(network)
        elif session.xenapi.network.get_MTU(network) != '1500':
            set_network_mtu(session, network, '1500')

def get_pool_management_device(session):
    """Returns the device used for XAPI mangagment"""
    device = None
    pifs = session.xenapi.PIF.get_all()
    for pif in pifs:
        if session.xenapi.PIF.get_management(pif):
            device_name = session.xenapi.PIF.get_device(pif)
            if device:
                if device_name != device:
                    raise TestCaseError("""Error: Different device names are marked as management. Check that there are no residual bonds.""")
            else:
                device = device_name
    return device
        
def get_module_names(name_filter):
    """Returns a list of modules which can be seen in the callers scope,
    filtering their names by the given filter."""
    modules = []
    #Get all of the modules names currently in scope
    for module in sys.modules.keys():
        #Apply filter
        if name_filter in module:
            modules.append(module)
    return modules

def change_vm_power_state(session, vm_ref):
    """Toggles VM powerstate between halted and running"""
    vm_power_state = session.xenapi.VM.get_power_state(vm_ref)
    print "Current VM power state: %s" % vm_power_state
    if vm_power_state == 'Running':
        log.debug("%s is shutting down" % vm_ref)
        session.xenapi.VM.clean_shutdown(vm_ref)
        log.debug("%s shutdown complete" % vm_ref)
    elif vm_power_state == 'Halted':
        log.debug("%s is booting" % vm_ref)
        session.xenapi.VM.start(vm_ref, False, False)

def arg_encode(string):
    """Encode a string for sending over XML-RPC to plugin"""
    return string.replace('/', '&#47;').replace('.', '&#46;')

def droid_template_import(session, sr_uuid):
    """Import the droid template into the specified SR"""
    #Note, the filename should be fully specified.
    args = {'sr_uuid': sr_uuid}
    return call_ack_plugin(session, 'droid_template_import', args)  

def get_default_sr(session):
    """Returns the SR reference marked as default in the pool"""
    pool_ref = session.xenapi.pool.get_all()[0]
    sr_ref = session.xenapi.pool.get_default_SR(pool_ref)
    try:
        #A call to check 'freshness' of default SR reference
        log.debug("Default SR: %s" % session.xenapi.SR.get_name_label(sr_ref))
        return sr_ref
    except XenAPI.Failure, exn:
        if exn.details[0] == 'HANDLE_INVALID':
            raise Exception("Pool is not configured to have shared storage!")
        else:
            raise exn
        
def get_local_sr(session, host):
    """Returns the ref object the local SR on the master host"""
    all_pbds = session.xenapi.PBD.get_all_records()
    all_srs = session.xenapi.SR.get_all_records()
    for pbd_ref, pbd_rec in all_pbds.iteritems():
        if host in pbd_rec['host']:
            for sr_ref, sr_rec in all_srs.iteritems():
                if 'Local storage' in sr_rec['name_label']:
                    if pbd_rec['SR'] in sr_ref:
                        return sr_ref
    raise Exception("No local SR attached to the master host")    

def import_droid_vm(session, creds=None, loc=DROID_VM_LOC):
    """Import VM template from Dom0 for use in tests"""
    sr_ref = get_default_sr(session)
    sr_uuid = session.xenapi.SR.get_uuid(sr_ref)
    vm_uuid = droid_template_import(session, sr_uuid)
    vm_ref = session.xenapi.VM.get_by_uuid(vm_uuid)
    convert_to_template(session, vm_ref)
    brand_vm(session, vm_ref, DROID_TEMPLATE_TAG)
    session.xenapi.VM.set_name_label(vm_ref, 'Droid VM')
    return vm_ref

def prepare_droid_vm(session, sr_ref, creds=None):
    """Checks if the droid vm needs to be installed
    on the host - if it does, it prepares it"""
    log.debug("About to prepare droid vm on SR %s" % sr_ref)
    vms = session.xenapi.VM.get_all_records()
    for ref, rec in vms.iteritems():
        if DROID_TEMPLATE_TAG in rec['other_config'] and rec['is_a_template']:
            return ref
    log.debug("No droid vm template exists - import one")
    #Else - if no templates exist
    return import_droid_vm(session, creds)

def run_xapi_async_tasks(session, funcs, timeout=300):
    """Execute a list of async functions, only returning when
    all of the tasks have completed."""
    task_refs = []

    for f in funcs:
        task_refs.append(f())

    start = time.time()

    results = []
    while task_refs:
        ref = task_refs.pop(0) #take the first item off
        log.debug("Current Task: %s" % ref)
        status = session.xenapi.task.get_status(ref)
        if status == "success":
            log.debug("%s has finished" % ref)
            result = session.xenapi.task.get_result(ref)

            log.debug("Result = %s" % result)
            if result.startswith('<value>'):
                results.append(result.split('value')[1].strip('</>'))
            else:
                #Some Async calls have no return value
                results.append(result)
        elif status == "failure":
            #The task has failed, and the error should be propogated upwards.
            raise Exception("Async call failed with error: %s" % session.xenapi.task.get_error_info(ref))
        else:
            log.debug("Task Status: %s" % status)
            #task has not finished, so re-attach to list
            task_refs.append(ref)

        if should_timeout(start, timeout):
            raise Exception("Async calls took too long to complete!" + 
                            "Perhaps, the operation has stalled? %d" % timeout)
        time.sleep(1)
    return results        

def deploy_count_droid_vms_on_host(session, host_ref, network_refs, vm_count, sms=None, sr_ref=None):
    """Deploy vm_count VMs on the host_ref host. Required 
    to define the network, optionally the SR"""
    if not sr_ref:
        sr_ref = get_default_sr(session)

    log.debug("Creating required VM(s)")
        
    droid_template_ref = prepare_droid_vm(session, sr_ref)
    
    task_list = []
    vm_ref_list = []
    for i in range(vm_count):
        vm_name = ('Droid %s' % (i + 1))
        log.debug("About to clone new VM: %s" % vm_name)
        vm_ref = session.xenapi.VM.clone(droid_template_ref, vm_name)
        log.debug("New VM reference = %s" % vm_ref)
        brand_vm(session, vm_ref, FOR_CLEANUP)
        session.xenapi.VM.set_is_a_template(vm_ref, False)
        make_vm_noninteractive(session, vm_ref)
        
        x = 0
        for network_ref in network_refs:
            log.debug("Setup vm (%s) eth%d on network (%s)" % (vm_ref, x, network_ref))
            setup_vm_on_network(session, vm_ref, network_ref, 'eth%d' % x, wipe=(x==0))

            if sms and network_ref in sms.keys() and sms[network_ref]:
                static_manager = sms[network_ref]
                ip = static_manager.get_ip()
                log.debug("IP: %s Netmask: %s Gateway: %s" % (ip.addr, ip.netmask, ip.gateway))
                droid_set_static(session, vm_ref, 'ipv4', 'eth%d' % x, ip.addr, ip.netmask, ip.gateway)
            # Increment interface counter
            x = x + 1

        # Add VM to startup list
        log.debug("Adding VM to startup list: %s" % vm_ref)
        task_list.append(lambda x=vm_ref: session.xenapi.Async.VM.start_on(x, host_ref, False, False))
        vm_ref_list.append(vm_ref)

    # Starting VMs async
    log.debug("Starting up all VMs")
    run_xapi_async_tasks(session, task_list)
    
    # Wait for IPs to be returned
    log.debug("Wait for IPs...")
    for vm_ref in vm_ref_list:
        wait_for_ip(session, vm_ref, 'eth0')
    log.debug("IP's retrieved...")

    # Check the VMs are in the 'Running' state.
    wait_for_vms(session, vm_ref_list, XAPI_RUNNING_STATE)
    
    return vm_ref_list

def wait_for_vms(session, vm_refs, power_state, timeout=60):
    """Wait for XAPI to mark each VM in the list as 'Running'"""
    log.debug("wait_for_vms: %s to reach state '%s'" % (vm_refs,
                                                        power_state))
    # Copy list
    vms = list(vm_refs)

    start = time.time()
    while vms and not should_timeout(start, timeout):
        vm = vms.pop()
        if session.xenapi.VM.get_power_state(vm) != power_state:
            vms.append(vm)

    if vms:
        # Our vm list should be empty if we have not timed out.
        for vm in vms:
            log.debug("VM not in '%s' state. Instead in '%s' state." %
                      (power_state, session.xenapi.VM.get_power_state(vm)))
        
        # We should raise an exception.
        raise Exception("VMs (%s) were not moved to the '%s' state in the provided timeout ('%d')" % (vms, power_state, timeout))
        


def deploy_slave_droid_vm(session, network_refs, sms=None):
    """Deploy a single VM on the slave host. This might be useful for
    tests between Dom0 and a VM. The Dom0 of the master is used for running
    commands, whilst the VM on the slave is used as a target"""
    
    def_sr = get_default_sr(session)
    host_slave_refs = get_pool_slaves(session)

    if len(host_slave_refs) == 0:
        raise Exception("ERROR: There appears to only be one host in this pool." + 
                        " Please add another host and retry.")

    #Pick the first slave reference    
    host_slave_ref = host_slave_refs[0]
            
    log.debug("Creating required VM")
        
    droid_template_ref = prepare_droid_vm(session, def_sr)
    vm_ref = session.xenapi.VM.clone(droid_template_ref, 'Droid 1')
    
    brand_vm(session, vm_ref, FOR_CLEANUP)
    session.xenapi.VM.set_is_a_template(vm_ref, False)
    make_vm_noninteractive(session, vm_ref)

    i = 0
    for network_ref in network_refs:
        log.debug("Setting interface up for eth%d (network_ref = %s)" % (i, network_ref))
        setup_vm_on_network(session, vm_ref, network_ref, 'eth%d' % i, wipe=(i==0))

    
        if sms and network_ref in sms.keys() and sms[network_ref]:
            static_manager = sms[network_ref]
            ip = static_manager.get_ip()
            log.debug("IP: %s Netmask: %s Gateway: %s" % (ip.addr, ip.netmask, ip.gateway))
            droid_set_static(session, vm_ref, 'ipv4', 'eth%d' % i, ip.addr, ip.netmask, ip.gateway)

        # Increment the counter
        i = i + 1

    log.debug("Starting required VM %s" % vm_ref)
    session.xenapi.VM.start_on(vm_ref, host_slave_ref, False, False)

    #Temp fix for establishing that a VM has fully booted before
    #continuing with executing commands against it.
    wait_for_ip(session, vm_ref, 'eth0')

    return vm_ref


def deploy_two_droid_vms(session, network_refs, sms=None):
    """A utility method for setting up two VMs, one on the primary host,
    and one on a slave host"""
    
    def_sr = get_default_sr(session)
    
    host_master_ref = get_pool_master(session)
    host_slave_refs = get_pool_slaves(session)

    if len(host_slave_refs) == 0:
        raise Exception("ERROR: There appears to only be one host in this pool." + 
                        " Please add another host and retry.")
    
    host_slave_ref = host_slave_refs[0]
            
    log.debug("Creating required VMs")
        
    def_sr = get_default_sr(session)
        
    droid_template_ref = prepare_droid_vm(session, def_sr)

    results = run_xapi_async_tasks(session,
              [lambda: session.xenapi.Async.VM.clone(droid_template_ref,
                                                     'Droid 1'),
               lambda: session.xenapi.Async.VM.clone(droid_template_ref,
                                                     'Droid 2')])

    if len(results) != 2:
        raise Exception("Expect to clone 2 vms - only got %d results" \
                            % len(results))

    vm1_ref = results[0] #Droid 1
    vm2_ref = results[1] #Droid 2
            
    brand_vm(session, vm1_ref, FOR_CLEANUP)
    brand_vm(session, vm2_ref, FOR_CLEANUP)

    session.xenapi.VM.set_is_a_template(vm1_ref, False)
    session.xenapi.VM.set_is_a_template(vm2_ref, False)
            
    make_vm_noninteractive(session, vm1_ref)
    make_vm_noninteractive(session, vm2_ref)
            
    log.debug("Setup vms on network")
    i = 0
    for network_ref in network_refs:
        log.debug("Setting interfaces up for eth%d" % i)
        # Note: only remove all existing networks on first run.
        setup_vm_on_network(session, vm1_ref, network_ref, 'eth%d' % i, wipe=(i==0))
        setup_vm_on_network(session, vm2_ref, network_ref, 'eth%d' % i, wipe=(i==0))

        log.debug("Static Manager Recs: %s" % sms)
        if sms and network_ref in sms.keys() and sms[network_ref]:
            static_manager = sms[network_ref]
            ip1 = static_manager.get_ip()
            ip2 = static_manager.get_ip()
            log.debug("1) IP: %s Netmask: %s Gateway: %s" % (ip1.addr, ip1.netmask, ip1.gateway))
            log.debug("2) IP: %s Netmask: %s Gateway: %s" % (ip2.addr, ip2.netmask, ip2.gateway))

            droid_set_static(session, vm1_ref, 'ipv4', 'eth%d' % i, 
                             ip1.addr, ip1.netmask, ip1.gateway)
            droid_set_static(session, vm2_ref, 'ipv4', 'eth%d' % i, 
                             ip2.addr, ip2.netmask, ip2.gateway)
        
        # Increment the counter
        i = i + 1

    log.debug("Starting required VMs")

    run_xapi_async_tasks(session, \
           [lambda: session.xenapi.Async.VM.start_on(vm1_ref,
                                                     host_master_ref,
                                                     False, False),
            lambda: session.xenapi.Async.VM.start_on(vm2_ref,
                                                     host_slave_ref,
                                                     False, False)])


    #Temp fix for establishing that a VM has fully booted before
    #continuing with executing commands against it.
    log.debug("Wait for IPs...")
    wait_for_ip(session, vm1_ref, 'eth0')
    wait_for_ip(session, vm2_ref, 'eth0')
    log.debug("IP's retrieved...")


    # Make plugin calls
    for vm_ref in [vm1_ref, vm2_ref]:
        # Install SSH Keys for Plugin operations
        call_ack_plugin(session, 'inject_ssh_key', 
                                {'vm_ref': vm_ref,
                                 'username': 'root',
                                 'password': DEFAULT_PASSWORD})
                                                    
        # Ensure that we make sure the switch accesses IP addresses by 
        # their own interfaces (avoid interface forwarding).        
        call_ack_plugin(session, 'reset_arp', {'vm_ref': vm_ref})

    return vm1_ref, vm2_ref

def droid_set_static(session, vm_ref, protocol, iface, ip, netmask, gw):
    args = {'vm_uuid': session.xenapi.VM.get_uuid(vm_ref),
            'protocol': protocol,
            'iface': iface,
            'ip': ip,
            'netmask': netmask,
            'gateway': gw}
    return call_ack_plugin(session, 'droid_set_static_conf', args)

def get_non_management_pifs(session):
    """Return a list of pif refs for non management devices"""
    pifs = session.xenapi.PIF.get_all_records()
    results = []
    for pif_ref, rec in pifs.iteritems():
        if not rec['management']:
            results.append(pif_ref)

    if not results:
        raise Exception("No management PIFs were found!")

    return results
    
class TimeoutFunction:
    """Wrapper class for providing a timemout for 
    the execution of a function"""

    def __init__(self, function, timeout, exception=''):
        self.timeout = timeout
        self.function = function
        self.exception = exception

    def handle_timeout(self, signum, frame):
        raise TimeoutFunctionException(self.exception)

    def __call__(self, *args):
        old = signal.signal(signal.SIGALRM, self.handle_timeout)
        signal.alarm(self.timeout)
        try:
            result = self.function(*args)
        finally:
            signal.signal(signal.SIGALRM, old)
        signal.alarm(0)
        return result

def xml_to_dicts(xml, tag):
    doc = minidom.parseString(xml.strip())
    try:
        result = []
        elems = doc.getElementsByTagName(tag)
        for el in elems:
            # Note that we have to convert this dictionary to non-unicode
            # strings, because we're being casual elsewhere.  That's why we're
            # not just returning dict(el.attributes.items()).
            item = {}
            for k, v in el.attributes.items():
                item[str(k)] = str(v)
            result.append(item)
    finally:
        doc.unlink()
    log.debug(result)
    return result

def call_ack_plugin(session, method, args={}):
    host = get_pool_master(session)
    return session.xenapi.host.call_plugin(host,
                                           'autocertkit',
                                           method,
                                           args)

def get_hw_offloads(session, device):
    """We want to call the XAPI plugin on the pool
    master to return the offload capabilites of a device."""

    xml_res = call_ack_plugin(session, 'get_hw_offloads',
                              {'eth_dev':device})

    return xml_to_dicts(xml_res, 'hw_offloads')[0]

def get_iface_statistics(session, vm_ref, iface): 
    xml_res = call_ack_plugin(session, 'get_iface_stats',
                                        {'iface':iface,
                                        'vm_ref': vm_ref})
    stats_dict = xml_to_dicts(xml_res, 'iface_stats')[0]
    return IfaceStats(iface, stats_dict)

def set_hw_offload(session, device, offload, state):
    """Call the a XAPI plugin on the pool master to set
    the state of an offload path on/off"""
    host = get_pool_master(session)    
    log.debug("Device: %s - Set %s %s" % (device, offload, state))
    res = session.xenapi.host.call_plugin(host,
                                          'autocertkit',
                                          'set_hw_offload',
                                          {'eth_dev': device,
                                           'offload': offload,
                                           'state': state})
    return res

def parse_csv_list(string):
    arr = string.split(',')
    res = []
    for item in arr:
        res.append(item.strip())
    return res

def set_nic_device_status(interface, status, creds=None):
    """Function to set an ifconfig ethX interface up or down"""
    log.debug("Bringing %s network interface %s" % (status, interface))
    call = ['ifconfig', interface, status]
    if not creds:
        res = make_local_call(call)
    else:
        res = ssh_command(creds['host'],
                          creds['user'],
                          creds['pass'],
                          ' '.join(call))
    time.sleep(5)
    return res

class TestThread(threading.Thread):
    """Threading class that runs a function"""
    def __init__(self, function):
        self.function = function
        threading.Thread.__init__(self)
    def run(self):
        self.function()

def create_test_thread(function):
    """Function for creating and starting a number of threads"""
    thread = TestThread(function)
    thread.start()
    return thread

def check_test_thread_status(threads):
    """Util function to check if test threads are still active,
    returns True if any are active, else False"""
    for thread in threads:
        if thread.isAlive():
            time.sleep(10)
            log.debug("Please be patient, the test is still running...")
            thread.join(20)
            return True
    return False

def get_master_network_devices(session):
    xml_devices = call_ack_plugin(session, 'get_network_devices')
    log.debug("Network Devices found on machine: '%s'" % xml_devices)
    return xml_to_dicts(xml_devices, 'device')

def get_local_storage_info(session):
    """Returns info about the local storage devices"""
    xml_devices = call_ack_plugin(session, 'get_local_storage_devices')
    log.debug("Local Storage Devices found on machine: '%s'" % xml_devices)
    return xml_to_dicts(xml_devices, 'device')

def get_xs_info(session):
    """Returns a limited subset of info about the XenServer version"""
    master_ref = get_pool_master(session)
    info = session.xenapi.host.get_software_version(master_ref)
    return {'version': info['product_version'],
            'build': info['build_number'],
            'xen': info['xen'],
            'xapi': info['xapi'],
            'date': info['date']}

def get_master_ifaces(session):
    devices = get_master_network_devices(session)
    ifaces = []
    for device in devices:
        ifaces.append(device['Kernel_name'])
    return ifaces

def set_dict_attributes(node, config):
    """Take a dict object, and set xmlnode attributes accordingly"""
    for k, v in config.iteritems():
        node.setAttribute(str(k), str(v))

def get_xml_attributes(node):
    """Return the xml attributes of a node as a dictionary object"""
    attr = {}
    for k, v in node._get_attributes().items():
        attr[k] = v
    return attr

def get_text_from_node_list(nlist, tag):
    for node in nlist:
        if node.nodeType == node.ELEMENT_NODE and node.tagName == tag:
            for subnode in node.childNodes:
                if subnode.nodeType == node.TEXT_NODE:
                    return subnode.data.strip()

def to_bool(string):
    """Convert string value of true/false to bool"""
    return string.upper() == "TRUE"

def get_value(rec, key, default=""):
    if key in rec.keys():
        return rec[key]
    else:
        return default
    
def print_documentation(object_name):
    print "--------- %s ---------" % bold(object_name)
    classes = enumerate_test_classes()
    for test_class_name, test_class in classes:
        arr = (object_name).split('.')
        if test_class_name == object_name:
            #get the class info
            print format(test_class.__doc__)
            print "%s: %s" % (bold('Prereqs'), test_class.required_config)
            sys.exit(0)
        elif len(arr) == 3 and ".".join(arr[:2]) == test_class_name:
            #get the method info
            print format(getattr(test_class, arr[2]).__doc__)
            sys.exit(0)

    print "The test name specified (%s) was incorrect. Please specify the full test name." % object_name
    sys.exit(0)

def bold(str):
    return "\033[1m%s\033[0;0m" % str

def format(str):
    """Format string to flow continuiously (without indents that have been inserted
    in order to make the docstring easy to follow"""
    arr = str.split('\n')
    arr = [item.strip() for item in arr]
    return " ".join(arr)

def enumerate_test_classes():
    tg = test_generators.TestGenerator('nonexistent_session')
    return tg.get_test_classes()

def read_valid_lines(filename):
    """Utility function for returning alist of uncommented lines (as indicated by '#')."""
    comment_symbols = ['#', ' ','\n']
    fh = open(filename, 'r')
    res = [line.strip() for line in fh.readlines()
           if line[0] not in comment_symbols]
    fh.close()
    return res

def set_network_mtu(session, network_ref, MTU):
    """Utility function for setting a network's MTU. MTU should be a string"""
    session.xenapi.network.set_MTU(network_ref, str(MTU))
    pifs = session.xenapi.network.get_PIFs(network_ref)        
    for pif in pifs:
        session.xenapi.PIF.unplug(pif)
        session.xenapi.PIF.plug(pif)

def intersection(lista, listb):
    """Return the intersection between two lists. Note,
    for duplicate values, each duplicate will be returned as 
    we merely check if item in lista, is in listb."""
    return [item for item in lista if item in listb]

def get_cpu_id(cpu_des):
    """Return an ID for a CPU based on their extended CPU
    string as returned via CPUID."""

    if not cpu_des:
        return "Unkown CPU ID"
    
    if 'intel' in cpu_des.lower():
        # Discard processor frequency
        tmp = cpu_des.split('@')[0]
        arr = tmp.split()
        return ' '.join(arr).replace('(R)', '')
    elif 'amd' in cpu_des.lower():
        return cpu_des.replace('(tm)', '')
        

def wait_for_hosts(session, timeout=300):
    log.debug("Wait for hosts to come back online...")
    hosts = session.xenapi.host.get_all()

    start = time.time()
    
    while hosts:
        host = hosts.pop(0)
        rec = session.xenapi.host.get_record(host)
        if not rec['enabled']:
            hosts.append(host)
            time.sleep(1)
        
        if should_timeout(start, timeout):
            raise Exception("Hosts failed to come back online %s for timeout %d" % 
                            (hosts, timeout))

    log.debug("Hosts are up.")

def get_ack_version(session, host):
    """Return the version string corresponding to the cert kit on a particular host"""
#    sw = session.xenapi.host.get_software_version(host)
#    key = 'xs:xs-auto-cert-kit'
#    if key in sw.keys():
#        return sw[key]
    if os.path.exists('/etc/xensource/installed-repos/xs:xs-auto-cert-kit'):
        return True
    else:
        return None

def combine_recs(rec1, rec2):
    """Utility function for combining two records into one."""
    rec = dict(rec1)
    for k, v in rec2.iteritems():
        if k in rec.keys():
            raise Exception("Cannot combine these recs, and keys overalp (%s)" % k)        
        rec[k] = v

    return rec

def check_vm_ping_response(session, vm_ref, interface='eth0', count=3, timeout=300):
    """Function to run a simple check that a VM responds to a ping from the XenServer"""
    # Get VM IP and start timeout
    vm_ip = wait_for_ip(session, vm_ref, interface)
    start = time.time()
    
    # Loop while waiting for an ICMP response
    while not should_timeout(start, timeout):
    
        call = ["ping", vm_ip, "-c %s" % count]
        
        # Make the local shell call
        log.debug("Checking for ping response from VM %s on interface %s at %s" % (vm_ref, interface, vm_ip))
        process = subprocess.Popen(call, stdout=subprocess.PIPE)
        stdout, stderr = process.communicate()
        response = str(stdout).strip()
        
        # Check for no packet loss. Note the space before '0%', this is required.
        if " 0% packet loss" in response:
            log.debug("Ping response received from %s" % vm_ip)
            return response
    
        log.debug("No ping response")
        time.sleep(3)
    
    raise Exception("VM %s interface %s could not be reached in the given timeout" % (vm_ref, interface))
