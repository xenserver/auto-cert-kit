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
import subprocess
import datetime
import XenAPI
import sys
import time
import ssh
from xml.dom import minidom
import tarfile
import signal
from datetime import datetime

import os
import base64
import threading
import re
import json
import binascii
import uuid

from acktools.net import route, generate_mac
import acktools.log

K = 1024
M = 1024 * K
G = 1024 * M

DROID_VM = 'droid_vm'
DEFAULT_PASSWORD = 'citrix'
FOR_CLEANUP = "for_cleanup"
DROID_TEMPLATE_TAG = "droid_vm_template"
REBOOT_ERROR_CODE = 3
REBOOT_FLAG_FILE = "/opt/xensource/packages/files/auto-cert-kit/reboot"
LOG_NAME = "auto-cert-kit"
LOG_LOC = "/var/log/auto-cert-kit.log"

# Capability Tags
REQ_CAP = "REQ"
MULTICAST_CAP = "MULTICAST"
SRIOV_CAP = "SR-IOV"

# XCP minimum version with SR-IOV support
XCP_MIN_VER_WITH_SRIOV = "2.6.0"

# XAPI States
XAPI_RUNNING_STATE = "Running"

# allow to use specific
vpx_dlvm_file = "vpx-dlvm.xva"

LSPCI = "/usr/sbin/lspci"


def configure_logging():
    """Method for configuring Logging"""
    global log
    log = acktools.log.configure_log(LOG_NAME, LOG_LOC)


configure_logging()


def release_logging():
    """Release logging object."""
    if log:
        acktools.log.release_log(log)


def log_basic_info(session):
    log.info("Auto Cert Kit Version: %s" % get_ack_version(session))
    log.info("Host Software Version: %s" % get_xs_info(session))
    log.info("Kernel Version       : %s" % get_kernel_version(session))
    log.info("Host Hardware Devices:\n%s" % get_system_info_tabular(session))


def init_ack_logging(session, rotate=True):
    release_logging()
    if rotate:
        for host_ref in session.xenapi.host.get_all():
            call_ack_plugin(session, 'run_ack_logrotate', {}, host=host_ref)
    configure_logging()
    log_basic_info(session)


def os_uptime():
    with open('/proc/uptime', 'r') as f:
        uptime_seconds = float(f.readline().split()[0])
        return uptime_seconds


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

# Exception Decorator


def log_exceptions(func):
    def decorated(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except XenAPI.Failure, e:
            log.error('%s: XenAPI.Failure: %s', func.__name__, str(e))
            raise
        except Exception, e:
            log.error('%s: %s: %s', func.__name__,
                      e.__class__.__name__, str(e))
            raise
    return decorated
#############################


def int_to_bin(x):
    if x == 0:
        return ''
    else:
        return int_to_bin(x / 2) + str(x % 2)


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

        for i in range(0, 4):
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
                raise Exception("Invalid netmask: '%s' ('%s')" %
                                (self.netmask, mask_str))

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
                raise Exception(
                    "Unexpected characted '%s' in binary string." % mask[i])

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


def get_network_routes(session, host_ref, retry=6):
    """Return a list of NetRoute objects for this system"""
    attempt = retry
    while attempt:
        attempt -= 1
        try:
            results = call_ack_plugin(
                session, 'get_host_routes', {}, host=host_ref)
        except:
            log.debug("Failed. retrying. (retry=%d)" % attempt)
            time.sleep(10)

    routes = []

    # Create NetRoute objects
    for rec in results:
        route_obj = route.Route(**rec)
        routes.append(route_obj)

    return routes


class StaticIPManager(object):
    """Class for managing static IP address provided by
    the caller. Allows us to do simple 'leasing' operations"""

    def __init__(self, conf):
        # Populate the internal list of IPs
        free = []
        for ip_addr in self.generate_ip_list(conf['ip_start'],
                                             conf['ip_end']):
            free.append(IPv4Addr(ip_addr,
                                 conf['netmask'],
                                 conf['gw']))

        self.ip_pool = free  # All the list of IPs
        self.in_use = []    # Index list of used IP from ip_pool.
        self.last_used = -1   # Index of IP lastly picked. Next will be 0.
        self.total_ips = len(free)

    def generate_ip_list(self, ip_start, ip_end):
        """Take an IP address start, and end, and compose a list of all 
        the IP addresses inbetween. E.g. '192.168.0.1' - '192.168.0.4' would
        return ['192.168.0.1', '192.168.0.2', '192.168.0.3', '192.168.0.4']."""

        def validate_ip(str_ip):
            try:
                arr = str_ip.split('.')
                res = []
                for i in range(0, 4):
                    res.append(int(arr[i]))
                    if res[i] > 254:
                        raise Exception("Invalid IP %s" % str_ip)
                return arr
            except Exception, e:
                raise Exception(
                    "Error: '%s' is not a valid IPv4 Addr (%s)" % (str_ip, str(e)))

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

        return "%s.%s.%s.%s" % (arr[0], arr[1], arr[2], arr[3])

    def get_ip(self):
        """Return an unused IP object (if one exists)"""
        if len(self.in_use) >= self.total_ips:
            raise Exception("Error: no more IP addresses to allocate! (%d in use)" %
                            len(self.in_use))

        index = (self.last_used + 1) % self.total_ips
        while True:
            if not index in self.in_use:
                self.last_used = index
                self.in_use.append(index)
                return self.ip_pool[index]
            index = (index + 1) % self.total_ips

    def return_ip(self, ip):
        """For a given IP object, attempt to remove from the 'in_use' list, and put
        it back into circulation for others to use"""
        if not ip in self.ip_pool:
            log.debug("IP(%s) does not exist in IP pool." % (ip,))
            raise Exception(
                "Trying to return an IP address that did not orginally exist!")

        index = self.ip_pool.index(ip)
        if index in self.in_use:
            log.debug("IP %s is in use. Removing..." % (ip,))
            self.in_use.remove(index)
        else:
            log.debug("IP %s is not in use. Passing." % (ip,))

    def release_all(self):
        """Return all of the IP addresses that are currently in use"""
        log.debug("Clearing in-use IP list.")
        self.in_use = []

    def available_ips(self):
        """Return number of unused IP in IP pool"""
        return self.total_ips - len(self.in_use)


class IfaceStats(object):
    """Class object for representing network statistics associated
       with an ethernet interface"""

    # List of keys depended on by callers
    required_keys = ['rx_bytes', 'tx_bytes', 'arch']

    def __init__(self, iface, rec):
        setattr(self, 'iface', iface)
        self.validate_args(rec)

        # Load all key/values into the class as attributes
        for k, v in rec.iteritems():
            try:
                setattr(self, k, int(v))
            except ValueError:
                setattr(self, k, str(v))

    def validate_args(self, rec):
        rec_keys = rec.keys()
        for key in self.required_keys:
            if key not in rec_keys:
                raise Exception("Error: could not find key '%s'" % key +
                                " in iface statistics record '%s'" % rec)


def is_64_bit(arch):
    """Check if platform type is 64 bit"""
    return arch in ['x86_64']


def value_in_range(value, min_v, max_v):
    """Establish whether a value lies between two numbers"""
    return min_v <= value <= max_v


def wrapped_value_in_range(value, min_v, max_v, wrap=4 * G):
    """The value is assumed to be wrapped at some point. The function
    must test whether the value falls within the expected range.
    e.g. if our range is between 15-25, but we wrap at 20, then the
    value '4' should be acceptable."""

    if value >= wrap:
        raise Exception("Error: the value is greater/equal than the wrap")

    if min_v > max_v:
        raise Exception("Error: min must be greated than max. %d %d" %
                        (min_v, max_v))

    if min_v - max_v >= wrap:
        raise Exception("Error: cannot accurately determine if value " +
                        "is in a range that is the space of a wrap")

    # This is a normal comparison opp
    if max_v < wrap:
        return value_in_range(value, min_v, max_v)

    # The range spans the wrap, there are two ranges we need
    # to check:
    #
    # 0------------y--------w
    # 0----z-----------------
    # We must check whether:
    #
    #  y > value < w or 0 > value > z

    min_v_wrapped = min_v % wrap
    max_v_wrapped = max_v % wrap

    # min_v_wrapped must be smaller (not equal)
    # if min_v_wrapped = max_v_wrapped then we must
    # accept a value that covers the entire range.
    if min_v_wrapped < max_v_wrapped:
        return value_in_range(value, min_v_wrapped, max_v_wrapped)
    else:
        pre_range = value_in_range(value, min_v_wrapped, wrap)
        post_range = value_in_range(value, 0, max_v_wrapped)

        return pre_range or post_range

    return False


class IperfTestStatsValidator(object):

    warn_threshold = 5
    error_threshold = 10

    def __init__(self, pre_stats, post_stats):
        setattr(self, 'pre', pre_stats)
        setattr(self, 'post', post_stats)

        assert pre_stats.arch == post_stats.arch
        setattr(self, 'arch', pre_stats.arch)

    def value_in_range(self, value, min_v, max_v):
        ret = value_in_range(value, min_v, max_v)
        if not ret and not is_64_bit(self.arch):
            log.debug("IfaceStats 32bit and value is not in rage."
                      "Try checking with wrapped value. (%s)" % self.arch)
            ret = wrapped_value_in_range(value, min_v, max_v, 4 * G)
        return ret

    def validate_bytes(self, sent_bytes, attr):
        pre_bytes = getattr(self.pre, attr)
        post_bytes = getattr(self.post, attr)

        low_lim = pre_bytes + sent_bytes
        warn_lim = low_lim + sent_bytes * self.warn_threshold / 100
        high_lim = low_lim + sent_bytes * self.error_threshold / 100

        log.debug("pre_bytes = %d" % pre_bytes)
        log.debug("post_bytes = %d" % post_bytes)
        log.debug("sent_bytes = %d" % sent_bytes)
        log.debug("low_lim = %d" % low_lim)
        log.debug("warn_lim = %d" % warn_lim)
        log.debug("high_lim = %d" % high_lim)

        if not self.value_in_range(post_bytes, low_lim, warn_lim):
            log.debug("Warning: limit not within warning range. (%d)" %
                      self.warn_threshold)

        if not self.value_in_range(post_bytes, low_lim, high_lim):
            raise Exception("Error: mismatch in expected number " +
                            " of bytes")
        return True


class Iface(object):
    """Class representing an ethernet interface"""

    required_keys = ["ip", "mask", "mac"]

    def __init__(self, rec):
        self.validate_rec(rec)

        for k, v in rec.iteritems():
            setattr(self, k, v)

    def validate_rec(self, rec):
        for key in self.required_keys:
            if key not in rec.keys():
                raise Exception("Error: invalid input rec '%s'" % rec)


def get_local_xapi_session():
    """Login to Xapi locally. This will only work if this script is being run 
    on Dom0. For this, no credentials are required."""
    session = XenAPI.xapi_local()
    session.login_with_password("", "")
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
    raise Exception(
        "Unexpected error. Cannot find control domain on host %s" % host_ref)


def get_master_control_domain(session):
    master_ref = get_pool_master(session)
    return _find_control_domain(session, master_ref)


def get_slave_control_domain(session):
    slave_refs = get_pool_slaves(session)
    if not slave_refs:
        raise Exception(
            "Error: the test kit requires a pool of at least 2 hosts.")
    # Only care about the first slave reference
    return _find_control_domain(session, slave_refs[0])


def set_reboot_flag(tc_info=None, flag_loc=REBOOT_FLAG_FILE):
    """Set an OS flag (i.e. touch a file) for when we're about to reboot.
    This is so that, on host reboot, we can work out whether we should
    run, and what the status of the kit is"""

    ffile = open(flag_loc, 'w')
    if tc_info:
        ffile.write(str(tc_info))
    ffile.close()


def get_reboot_flag(flag=REBOOT_FLAG_FILE):
    """Return a dictionary that contains information of when reboot was
    initiated."""

    if os.path.exists(flag):
        ffile = open(flag, 'r')
        flag_str = ffile.read().strip()
        ffile.close()

        if len(flag_str) > 0:
            tc_info = eval(flag_str)
            if isinstance(tc_info, dict):
                return tc_info

        return {'info': 'flag contains no previous running info.'}
    else:
        return None


def get_reboot_flag_timestamp(flag=REBOOT_FLAG_FILE):
    """Finding when reboot was initialised."""
    if os.path.exists(flag):
        time_str = time.ctime(os.path.getctime(flag))
        return datetime(*(time.strptime(time_str, "%a %b %d %H:%M:%S %Y")[0:6]))
    return None


def clear_reboot_flag(flag=REBOOT_FLAG_FILE):
    if os.path.exists(flag):
        os.remove(flag)


def reboot_all_hosts(session):
    master = get_pool_master(session)
    hosts = session.xenapi.host.get_all()
    for host in hosts:
        session.xenapi.host.disable(host)
        if host != master:
            session.xenapi.host.reboot(host)
    session.xenapi.host.reboot(master)


def host_reboot(session):
    log.debug("Attempting to reboot the host")
    # Cleanup all the running vms
    pool_wide_cleanup(session)
    reboot_all_hosts(session)
    log.debug("Rebooted master")
    sys.exit(REBOOT_ERROR_CODE)


def host_crash(session, do_cleanup=False):
    """ Force crash master. The host will be rebooted once it crashes."""
    if do_cleanup:
        pool_wide_cleanup(session)

    # Synchronise XAPI DB to disk  before crash.
    session.xenapi.pool.sync_database()
    time.sleep(5)

    host = get_pool_master(session)
    log.debug("Crashing host: %s" % host)
    call_ack_plugin(session, 'force_crash_host')

    # Once it is successful, host will be crashed hence code should not reach
    # here.
    raise Exception("Failed to crash host.")


def retrieve_crashdumps(session, host=None, fromxapi=False):
    """Retrive all list of crashdump of master."""
    if not host:
        host = get_pool_master(session)
    cds = call_ack_plugin(session, 'retrieve_crashdumps', {
                          'host': host, 'from_xapi': str(fromxapi)})
    for cd in cds:
        cd['size'] = int(cd['size'])
        ts = cd['timestamp']
        if fromxapi:
            cd['timestamp'] = datetime(int(ts[:4]),  # year
                                       int(ts[4:6]),   # month
                                       int(ts[6:8]),   # day
                                       int(ts[9:11]),  # hour
                                       int(ts[12:14]),  # minute
                                       int(ts[15:17]))  # second
        else:
            cd['timestamp'] = datetime(int(ts[:4]),  # year
                                       int(ts[4:6]),   # month
                                       int(ts[6:8]),   # day
                                       int(ts[9:11]),  # hour
                                       int(ts[11:13]),  # minute
                                       int(ts[13:15]))  # second
    log.debug("Retained Crashdumps: %s" % str(cds))
    return cds


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
    return software['product_version']


def get_xcp_version(session):
    """Return the XCP version (using the master host)"""
    master_ref = get_pool_master(session)
    software = session.xenapi.host.get_software_version(master_ref)
    return software['platform_version']


def get_kernel_version(session):
    """Return kernel version using uname"""
    return call_ack_plugin(session, 'get_kernel_version')


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


def create_network(session, name_label, description, other_config):
    """Method for creating a XAPI network"""
    net_ref = session.xenapi.network.create({'name_label': name_label,
                                             'description': description,
                                             'other_config': other_config})
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
    log.debug("Bond %s is created." % net_ref)
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


def get_physical_devices_by_network(session, network):
    """Taking a network, enumerate the list of physical devices attached 
    to each component PIF. This may require some unwrapping (e.g. bonds)
    to determine all the consituent physical PIFs."""

    def get_physical_pifs(session, pifs):
        res = []
        for pif in pifs:
            pif_rec = session.xenapi.PIF.get_record(pif)
            if pif_rec['physical']:
                res.append(pif)
            elif pif_rec['bond_master_of']:
                for bond in pif_rec['bond_master_of']:
                    bond_pifs = session.xenapi.Bond.get_slaves(bond)
                    res = res + get_physical_pifs(session, bond_pifs)
            elif pif_rec['VLAN_master_of'] != 'OpaqueRef:NULL':
                log.debug("VLAN PIF found: %s." % pif_rec)
                vlan_obj = session.xenapi.VLAN.get_record(
                    pif_rec['VLAN_master_of'])
                res = res + \
                    get_physical_pifs(session, [vlan_obj['tagged_PIF']])
            else:
                raise Exception(
                    "Error: %s is not physical, bond or VLAN" % pif_rec)
        return res

    pifs = session.xenapi.network.get_PIFs(network)
    physical_pifs = get_physical_pifs(session, pifs)

    devices = []
    for pif in physical_pifs:
        device = session.xenapi.PIF.get_device(pif)
        if device not in devices:
            devices.append(device)

    if not devices:
        raise Exception("Error: no PIFs for network %s" % network)

    if len(devices) > 1:
        log.debug("More than one device for network %s: %s" % (network,
                                                               devices))
    return devices


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
    ifaces = [dev['Kernel_name']
              for dev in devices if device['PCI_id'] == dev['PCI_id']]
    log.debug("Equivalent devices for %s: %s" % (device, ifaces))
    return ifaces


def has_sriov_cap(session, device):
    master_ref = get_pool_master(session)
    pifs_ref = get_pifs_by_device(session, device, [master_ref])
    caps = session.xenapi.PIF.get_capabilities(pifs_ref[0])
    return 'sriov' in caps


def enable_vf(session, device, host, network_label):
    pifs_ref = get_pifs_by_device(session, device, [host])
    net_ref = create_network(session, network_label, '', {})
    net_sriov_ref = session.xenapi.network_sriov.create(pifs_ref[0], net_ref)
    # no "other_config" field for FOR_CLEANUP

    return (net_ref, net_sriov_ref)


def get_test_sriov_network(session, network_label):
    networks = session.xenapi.network.get_all()
    for net in networks:
        label = session.xenapi.network.get_name_label(net)
        if label == network_label:
            return net

    return None


def is_vf_disabled(session):
    cmd = b"%s | grep 'Virtual Function' | wc -l" % LSPCI
    cmd = binascii.hexlify(cmd)
    sum = 0
    for host in session.xenapi.host.get_all():
        res = call_ack_plugin(session, 'shell_run', {'cmd': cmd}, host)
        res = res.pop()
        log.debug("Found %s VF on host %s" % (res["stdout"], str(host)))
        sum += int(res["stdout"]) if int(res["returncode"]) == 0 else 1
    log.debug("Found total %d VF" % sum)

    return sum == 0


def get_management_network(session):
    networks = session.xenapi.network.get_all()
    for network in networks:
        pifs = session.xenapi.network.get_PIFs(network)
        for pif in pifs:
            if session.xenapi.PIF.get_management(pif):
                return network

    raise Exception("ERROR: No management network found!")


def get_management_interface(session, host):
    # this is for backward compatibility.
    # host.get_management_interface is added in XenServer 6.1
    # pif = session.xenapi.host.get_management_interface(host)
    for pif in session.xenapi.host.get_PIFs(host):
        if session.xenapi.PIF.get_management(pif):
            return pif

    raise Exception("ERROR: No management interface found!")


def create_vlan(session, pif_ref, network_ref, vlan_id):
    """Create a VLAN PIF from an existing physical PIF on the specified
    network"""
    log.debug("About to create_vlan")
    return session.xenapi.VLAN.create(pif_ref, str(vlan_id), network_ref)


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
        # 1. Remove all existings VIFs
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
    # 2. Create a new VIF attached to the specified network reference
    vif_ref = create_vif(session, iface.replace('eth', ''),
                         network_ref, vm_ref, mac=generate_mac())

    if session.xenapi.VM.get_power_state(vm_ref) == "Running":
        log.debug("Plug VIF %s" % vif_ref)
        session.xenapi.VIF.plug(vif_ref)

    return vif_ref


def make_vm_noninteractive(session, vm_ref):
    """Set PV args to ensure the Demo VM boots up automatically,
    without requring a user to add a password"""
    session.xenapi.VM.set_PV_args(vm_ref, 'noninteractive')


def should_timeout(start, timeout):
    """Method for evaluating whether a time limit has been met"""
    return time.time() - start > float(timeout)


def _get_control_domain_ip(session, vm_ref, device='xenbr0'):
    """Return the IP address for a specified control domain"""
    if not session.xenapi.VM.get_is_control_domain(vm_ref):
        raise Exception("Specified VM is not a control domain")

    host_ref = session.xenapi.VM.get_resident_on(vm_ref)
    return call_ack_plugin(session, 'get_local_device_ip', {'device': device},
                           host_ref)


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
        log.debug("Control domain %s has IP %s on device %s" %
                  (vm_ref, ipaddr, device))
        return ipaddr

    if not device.startswith('eth'):
        raise Exception(
            "Invalid device specified, it should be in the format 'ethX'")

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


def wait_for_all_ips(session, vm_ref, timeout=300):
    """wait for all interface to have IPs"""

    ips = {}
    if session.xenapi.VM.get_is_control_domain(vm_ref):
        host_ref = session.xenapi.VM.resident_on(vm_ref)
        for pif in session.xenapi.PIF.get_all():
            if host_ref == session.xenapi.PIF.get_host(pif):
                device = 'eth' + \
                    str(session.xenapi.PIF.get_device(pif)).strip()
                ips[device] = _get_control_domain_ip(session, vm_ref, device)

    else:
        for vif in session.xenapi.VIF.get_all():
            if vm_ref == session.xenapi.VIF.get_VM(vif):
                device = 'eth' + \
                    str(session.xenapi.VIF.get_device(vif)).strip()
                ips[device] = wait_for_ip(session, vm_ref, device, timeout)

    return ips


def _is_link_up(statedict):
    """Evaluate current operstate, carrier and link from dict."""

    if statedict['link'] == 'yes' and statedict['carrier'] == 'running' and statedict['operstate'] == 'up':
        return True
    return False


def wait_for_linkstate(session, device, state, host_ref=None, timeout=60):
    """Wait for interface to be a given state."""

    args = {'device': device}
    start = time.time()
    while not should_timeout(start, timeout):
        results = call_ack_plugin(
            session, 'get_local_device_linkstate', args, host_ref)
        cur_state = results[0]
        log.debug("Current linkstate of %s on host %s is %s." %
                  (device, host_ref, cur_state))
        if state.lower() == 'up' and _is_link_up(cur_state):
            return
        if state.lower() == 'down' and not _is_link_up(cur_state):
            return

        time.sleep(2)

    raise Exception("Timeout has been exceeded waiting for %s on %s changed to %s"
                    % (device, host_ref, state))


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
    result = ssh_command(vm_ip, username, password,
                         cmd_str, attempts=10)["stdout"].split('\n')
    log.debug("Results= %s" % result)
    for line in result:
        log.debug("SSH Line: %s" % line)
        if 'transmitted' in line:
            return line
    raise TestCaseError("""Error: Unexpected response 
                       from ping, to transmission statistics: %s"""
                        % result)


@log_exceptions
def ssh_command(ip, username, password, cmd_str, dbg_str=None, attempts=10):
    """execute an SSH command using the parimiko library, return both
    exit code, stdout and stderr."""
    if dbg_str:
        log.debug(dbg_str)

    # use uuid as random string
    flag = "__%s__" % str(uuid.uuid4())
    of = "/tmp/ack.stdout.%s.txt" % flag
    ef = "/tmp/ack.stderr.%s.txt" % flag

    # put cmd_str into single quotes and sh to run with redirection, e.g.
    #   echo "$HOME" | sed 's/\///g'
    #   sh -c 'echo "$HOME" | sed '\''s/\///g'\''' 1>of 2>ef
    cmd_s = cmd_str.replace("'", r"'\''")
    cmd_s = '''sh -c '%s' 1>%s 2>%s''' % (cmd_s, of, ef)
    # catch exit code, stdout and stderr
    cmd = '''%s; echo -n "$?%s"; cat %s; echo -n "%s"; cat %s; rm -f %s %s;''' % \
          (cmd_s, flag, of, flag, ef, of, ef)

    for i in range(0, attempts):
        log.debug("Attempt %d/%d: %s" % (i, attempts, cmd))

        try:
            sshcmd = ssh.SSHCommand(ip, cmd, log, username, 900, password)
            output = sshcmd.read("string")
        except Exception, e:
            log.debug("Exception: %s" % str(e))
            # Sleep before next attempt
            time.sleep(20)
            continue

        ret = output.split(flag)
        if len(ret) == 3:
            return {"returncode": int(ret[0]), "stdout": ret[1], "stderr": ret[2]}

    log.debug("Max attempt reached %d/%d" % (attempts, attempts))
    return {"returncode": -1, "stdout": "", "stderr": "An unkown error has occured!"}


def plug_pif(session, pif):
    """ Plug given pif"""
    log.debug("Plugging PIF: %s" % pif)
    session.xenapi.PIF.plug(pif)


def unplug_pif(session, pif):
    """Unplug a PIF"""
    if session.xenapi.PIF.get_disallow_unplug(pif):
        log.debug("PIF: %s is disallowed to unplug. Change setting." % pif)
        session.xenapi.PIF.set_disallow_unplug(pif, False)
    log.debug("Unplugging PIF: %s" % pif)
    session.xenapi.PIF.unplug(pif)


def destroy_pif(session, pif):
    """Unplug and destroy pif"""
    unplug_pif(session, pif)
    session.xenapi.PIF.destroy(pif)


def destroy_vm(session, vm_ref, timeout=60):
    """Checks powerstate of a VM, destroys associated VDIs, 
    and destroys VM once shutdown"""

    log.debug("Destroying VM: %s" % vm_ref)

    # If there is an on going operation, give some time to finish.
    start = time.time()
    cur_oper = session.xenapi.VM.get_current_operations(vm_ref)
    while len(cur_oper):
        log.debug("Found %s operations in action." % str(cur_oper))
        time.sleep(5)
        if should_timeout(start, 15):
            break
        cur_oper = session.xenapi.VM.get_current_operations(vm_ref)

    start = time.time()
    power_state = session.xenapi.VM.get_power_state(vm_ref)
    cur_oper = session.xenapi.VM.get_current_operations(vm_ref)
    while power_state != 'Halted' or len(cur_oper) > 0:
        log.debug("VM is %s with %s in action." % (power_state, str(cur_oper)))
        if should_timeout(start, timeout):
            raise Exception("Failed to stop VM or VM is not in right state. (VM: %s, power_state: %s)" % (
                vm_ref, power_state))
        log.debug("Trying shutting down VM: %s" % vm_ref)
        # Due to timing issue this may fail as it tries to shutdown halted VM.
        try:
            session.xenapi.VM.hard_shutdown(vm_ref)
        except Exception, e:
            log.error(str(e))
            log.debug(
                "Failed to hard shutdown VM. Trying again in a few seconds.")
        time.sleep(5)

        power_state = session.xenapi.VM.get_power_state(vm_ref)
        cur_oper = session.xenapi.VM.get_current_operations(vm_ref)

    log.debug("VM %s is ready to be removed." % vm_ref)

    # Check that the VDI is not in-use
    vbd_refs = session.xenapi.VM.get_VBDs(vm_ref)
    for vbd_ref in vbd_refs:
        vdi_ref = session.xenapi.VBD.get_VDI(vbd_ref)
        log.debug("Destroying VDI %s" % vdi_ref)
        try:
            start = time.time()
            ops_list = session.xenapi.VDI.get_allowed_operations(vdi_ref)
            while 'destroy' not in ops_list:
                time.sleep(2)
                ops_list = session.xenapi.VDI.get_allowed_operations(vdi_ref)
                if should_timeout(start, timeout):
                    raise Exception("Cannot destroy VDI: VDI is still active")
            # If the VDI is free, try to destroy it. Should pass the exception
            # catch if it is a NULL VDI reference.
            session.xenapi.VDI.destroy(vdi_ref)
        except XenAPI.Failure, exn:
            if exn.details[0] == 'HANDLE_INVALID':
                pass
            else:
                raise exn
    # Finally, destroy the VM
    log.debug("Destroying VM %s" % vm_ref)
    session.xenapi.VM.destroy(vm_ref)


def pool_wide_cleanup(session, tag=FOR_CLEANUP):
    """This function will look for all the object with a given tag,
    and remove them as part of a cleanup operation"""
    log.debug("**Performing pool wide cleanup...**")
    pool_wide_vm_cleanup(session, tag)
    pool_wide_network_sriov_cleanup(session, tag)
    pool_wide_network_cleanup(session, tag)
    pool_wide_host_cleanup(session)


def host_cleanup(session, host):
    # Check routes
    routes = get_network_routes(session, host)
    cur_route_table = route.RouteTable(routes)

    oc = session.xenapi.host.get_other_config(host)

    # Load in default routes
    default_route_key = 'default_routes'
    default_route_list = []
    if default_route_key in oc.keys():
        default_routes = eval(oc[default_route_key])
        for rec in default_routes:
            route_obj = route.Route(**rec)
            default_route_list.append(route_obj)

    default_route_table = route.RouteTable(default_route_list)
    missing_routes = default_route_table.get_missing(cur_route_table)

    dom0_ref = _find_control_domain(session, host)
    for missing_route in missing_routes:
        log.debug("Missing route: %s. Attempting to add to host %s" %
                  (missing_route.get_record(), host))

        args = {'vm_ref': dom0_ref,
                'dest_ip': missing_route.get_dest(),
                'device': missing_route.get_iface(),
                'gw': missing_route.get_gw(),
                'mask': missing_route.get_mask()}
        call_ack_plugin(session, 'add_route', args, host)

    log.debug("host cleanup is complete.")


def pool_wide_host_cleanup(session):
    hosts = session.xenapi.host.get_all()

    for host in hosts:
        host_cleanup(session, host)


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


def pool_wide_network_sriov_cleanup(session, tag):
    """Searches for network sriov, and destroys"""

    if get_xcp_version(session) < XCP_MIN_VER_WITH_SRIOV:
        return

    sriov_nets = session.xenapi.network_sriov.get_all()
    for network in sriov_nets:
        # no "other_config" field for FOR_CLEANUP, so cleanup all
        session.xenapi.network_sriov.destroy(network)


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
            log.debug("Pifs to cleanup: %s from network %s" % (pifs, network))
            for pif in pifs:
                destroy_pif(session, pif)
            session.xenapi.network.destroy(network)
        elif session.xenapi.network.get_MTU(network) != '1500':
            set_network_mtu(session, network, '1500')
    for host in session.xenapi.host.get_all():
        for pif in session.xenapi.host.get_PIFs(host):
            oc = session.xenapi.PIF.get_other_config(pif)
            if oc.pop(tag, None):
                log.debug("Pif to cleanup: %s from host %s" % (pif, host))
                call_ack_plugin(session, 'flush_local_device',
                                {'device': session.xenapi.PIF.get_device(pif)},
                                host=host)
                session.xenapi.PIF.set_other_config(pif, oc)


def get_pool_management_device(session):
    """Returns the device used for XAPI mangagment"""
    device = None
    pifs = session.xenapi.PIF.get_all()
    for pif in pifs:
        if session.xenapi.PIF.get_management(pif):
            device_name = session.xenapi.PIF.get_device(pif)
            if device:
                if device_name != device:
                    raise TestCaseError(
                        """Error: Different device names are marked as management. Check that there are no residual bonds.""")
            else:
                device = device_name
    return device


def get_module_names(name_filter):
    """Returns a list of modules which can be seen in the callers scope,
    filtering their names by the given filter."""
    modules = []
    # Get all of the modules names currently in scope
    for module in sys.modules.keys():
        # Apply filter
        if name_filter in module:
            modules.append(module)
    return modules


def droid_template_import(session, host_ref, sr_uuid):
    """Import the droid template into the specified SR"""
    # Note, the filename should be fully specified.
    args = {'sr_uuid': sr_uuid, 'vpx_dlvm_file': vpx_dlvm_file}
    return call_ack_plugin(session, 'droid_template_import', args, host=host_ref)


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


def assert_sr_connected(session, sr_ref, host_ref):
    """Assert that a given SR is connected to a host"""
    pbds = session.xenapi.SR.get_PBDs(sr_ref)
    for pbd in pbds:
        if session.xenapi.PBD.get_host(pbd) == host_ref:
            log.debug("SR %s connected to host %s" % (session.xenapi.SR.get_uuid(
                sr_ref), session.xenapi.host.get_name_label(host_ref)))
            return True
    return False


def find_storage_for_host(session, host_ref, exclude_types=['iso', 'udev']):
    """Given a host reference, return available storage"""
    srs = session.xenapi.SR.get_all()

    # Find relevent SRs based on whether they're connected to host
    rel_srs = [sr for sr in srs
               if assert_sr_connected(session, sr, host_ref) and
               session.xenapi.SR.get_type(sr) not in exclude_types]

    log.debug("Available SRs for host '%s': '%s'" % (host_ref, rel_srs))

    log.debug("Host: %s" % session.xenapi.host.get_name_label(host_ref))
    for sr in rel_srs:
        log.debug("SR: %s" % session.xenapi.SR.get_name_label(sr))
    return rel_srs


def import_droid_vm(session, host_ref, creds=None):
    """Import VM template from Dom0 for use in tests"""
    sr_refs = find_storage_for_host(session, host_ref)

    if not sr_refs:
        raise Exception(
            "Error: could not find any available SRs for host '%s'" % host_ref)

    sr_ref = sr_refs.pop()
    log.debug("Importing droid VM to %s for use on host %s" %
              (session.xenapi.SR.get_name_label(sr_ref),
               session.xenapi.host.get_name_label(host_ref)))

    sr_uuid = session.xenapi.SR.get_uuid(sr_ref)
    vm_uuid = droid_template_import(session, host_ref, sr_uuid)
    vm_ref = session.xenapi.VM.get_by_uuid(vm_uuid)
    convert_to_template(session, vm_ref)
    brand_vm(session, vm_ref, DROID_TEMPLATE_TAG)
    session.xenapi.VM.set_name_label(vm_ref, 'Droid VM')
    return vm_ref


def find_droid_templates(session):
    """Returns a list of droid VM template refs"""
    refs = []
    vms = session.xenapi.VM.get_all_records()
    for ref, rec in vms.iteritems():
        if DROID_TEMPLATE_TAG in rec['other_config'] \
                and rec['is_a_template']:
            refs.append(ref)

    log.debug("find_droid_templates: found refs: '%s'" % refs)

    return refs


def get_vm_vdis(session, vm_ref):
    vbds = session.xenapi.VM.get_VBDs(vm_ref)
    vdis = [session.xenapi.VBD.get_VDI(vbd) for vbd in vbds]
    return [vdi for vdi in vdis if vdi != "OpaqueRef:NULL"]


def assert_can_boot_here(session, vm_ref, host_ref):
    vdis = get_vm_vdis(session, vm_ref)

    req_srs = list(set([session.xenapi.VDI.get_SR(vdi) for vdi in vdis]))
    log.debug("VM %s requires SRs '%s'" % (vm_ref, req_srs))

    for sr_ref in req_srs:
        if not assert_sr_connected(session, sr_ref, host_ref):
            return False

    log.debug("VM %s can boot on host %s" % (vm_ref, host_ref))
    return True


def prepare_droid_vm(session, host_ref, creds=None):
    """Checks if the droid vm needs to be installed
    on the host - if it does, it prepares it"""
    log.debug("About to prepare droid vm for host %s" % host_ref)

    templates = [template for template in find_droid_templates(session)
                 if assert_can_boot_here(session, template, host_ref)]

    if templates:
        # Any of the templates will do
        return templates.pop()
    else:
        log.debug("No droid vm template exists - import one")
        # Else - if no templates exist
        return import_droid_vm(session, host_ref, creds)


def run_xapi_async_tasks(session, funcs, timeout=300):
    """Execute a list of async functions, only returning when
    all of the tasks have completed."""
    task_refs = []

    i = 0
    for f in funcs:
        # Create a tuple with an index so that returned results
        # can keep the correct ordering.
        task_refs.append((i, f()))
        i = i + 1

    start = time.time()

    results = []
    while task_refs:
        idx, ref = task_refs.pop(0)  # take the first item off
        log.debug("Current Task: %s" % ref)
        status = session.xenapi.task.get_status(ref)
        if status == "success":
            log.debug("%s has finished" % ref)
            result = session.xenapi.task.get_result(ref)

            log.debug("Result = %s" % result)
            if result.startswith('<value>'):
                results.append((idx, result.split('value')[1].strip('</>')))
            else:
                # Some Async calls have no return value
                results.append((idx, result))
        elif status == "failure":
            # The task has failed, and the error should be propogated upwards.
            raise Exception("Async call failed with error: %s" %
                            session.xenapi.task.get_error_info(ref))
        else:
            log.debug("Task Status: %s" % status)
            # task has not finished, so re-attach to list
            task_refs.append((idx, ref))

        if should_timeout(start, timeout):
            # Change to TimeoutFunctionException to work-around CA-146164.
            # To avoid applying hotfixes, keeping this work-around.
            # raise Exception("Async calls took too long to complete!" +
            raise TimeoutFunctionException("Async calls took too long to complete!" +
                                           "Perhaps, the operation has stalled? %d" % timeout)
        time.sleep(1)

    # Sort the results in order of index
    results = sorted(results, key=lambda tup: tup[0])
    return [res for (_, res) in results]


def deploy_count_droid_vms_on_host(session, host_ref, network_refs, vm_count, sms=None, sr_ref=None):
    """Deploy vm_count VMs on the host_ref host. Required 
    to define the network, optionally the SR"""

    log.debug("Creating required VM(s)")

    droid_template_ref = prepare_droid_vm(session, host_ref)

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
            log.debug("Setup vm (%s) eth%d on network (%s)" %
                      (vm_ref, x, network_ref))
            setup_vm_on_network(session, vm_ref, network_ref,
                                'eth%d' % x, wipe=(x == 0))

            if sms and network_ref in sms.keys() and sms[network_ref]:
                static_manager = sms[network_ref]
                ip = static_manager.get_ip()
                log.debug("IP: %s Netmask: %s Gateway: %s" %
                          (ip.addr, ip.netmask, ip.gateway))
                droid_set_static(session, vm_ref, 'ipv4', 'eth%d' %
                                 x, ip.addr, ip.netmask, ip.gateway)
            # Increment interface counter
            x = x + 1

        # Add VM to startup list
        log.debug("Adding VM to startup list: %s" % vm_ref)
        task_list.append(lambda x=vm_ref: session.xenapi.Async.VM.start_on(
            x, host_ref, False, False))
        vm_ref_list.append(vm_ref)

    # Starting VMs async
    log.debug("Starting up all VMs")
    run_xapi_async_tasks(session, task_list)

    # Wait for IPs to be returned
    log.debug("Wait for IPs...")
    for vm_ref in vm_ref_list:
        wait_for_all_ips(session, vm_ref)
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
        raise Exception("VMs (%s) were not moved to the '%s' state in the provided timeout ('%d')" % (
            vms, power_state, timeout))


def deploy_slave_droid_vm(session, network_refs, sms=None):
    """Deploy a single VM on the slave host. This might be useful for
    tests between Dom0 and a VM. The Dom0 of the master is used for running
    commands, whilst the VM on the slave is used as a target"""

    host_slave_refs = get_pool_slaves(session)

    if len(host_slave_refs) == 0:
        raise Exception("ERROR: There appears to only be one host in this pool." +
                        " Please add another host and retry.")

    # Pick the first slave reference
    host_slave_ref = host_slave_refs[0]

    log.debug("Creating required VM")

    droid_template_ref = prepare_droid_vm(session, host_slave_ref)
    vm_ref = session.xenapi.VM.clone(droid_template_ref, 'Droid 1')

    brand_vm(session, vm_ref, FOR_CLEANUP)
    session.xenapi.VM.set_is_a_template(vm_ref, False)
    make_vm_noninteractive(session, vm_ref)

    i = 0
    for network_ref in network_refs:
        log.debug("Setting interface up for eth%d (network_ref = %s)" %
                  (i, network_ref))
        setup_vm_on_network(session, vm_ref, network_ref,
                            'eth%d' % i, wipe=(i == 0))

        if sms and network_ref in sms.keys() and sms[network_ref]:
            static_manager = sms[network_ref]
            ip = static_manager.get_ip()
            log.debug("IP: %s Netmask: %s Gateway: %s" %
                      (ip.addr, ip.netmask, ip.gateway))
            droid_set_static(session, vm_ref, 'ipv4', 'eth%d' %
                             i, ip.addr, ip.netmask, ip.gateway)

        # Increment the counter
        i = i + 1

    log.debug("Starting required VM %s" % vm_ref)
    session.xenapi.VM.start_on(vm_ref, host_slave_ref, False, False)

    # Temp fix for establishing that a VM has fully booted before
    # continuing with executing commands against it.
    wait_for_all_ips(session, vm_ref)

    return vm_ref


def import_two_droid_vms(session, network_refs, sms=None):
    """Import two VMs, one on the primary host, and one on a slave host"""

    host_master_ref = get_pool_master(session)
    host_slave_refs = get_pool_slaves(session)

    if len(host_slave_refs) == 0:
        raise Exception("ERROR: There appears to only be one host in this pool." +
                        " Please add another host and retry.")

    host_slave_ref = host_slave_refs[0]

    log.debug("Creating required VMs")

    # Get template references
    dmt_ref = prepare_droid_vm(session, host_master_ref)
    dst_ref = prepare_droid_vm(session, host_slave_ref)

    results = run_xapi_async_tasks(session,
                                   [lambda: session.xenapi.Async.VM.clone(dmt_ref,
                                                                          'Droid 1'),
                                    lambda: session.xenapi.Async.VM.clone(dst_ref,
                                                                          'Droid 2')])

    if len(results) != 2:
        raise Exception("Expect to clone 2 vms - only got %d results"
                        % len(results))

    vm1_ref = results[0]  # Droid 1
    vm2_ref = results[1]  # Droid 2

    brand_vm(session, vm1_ref, FOR_CLEANUP)
    brand_vm(session, vm2_ref, FOR_CLEANUP)

    session.xenapi.VM.set_is_a_template(vm1_ref, False)
    session.xenapi.VM.set_is_a_template(vm2_ref, False)

    make_vm_noninteractive(session, vm1_ref)
    make_vm_noninteractive(session, vm2_ref)

    return (host_master_ref, host_slave_ref, vm1_ref, vm2_ref)


def config_network_for_droid_vm(session, vm_ref, network_ref, did, sms=None):
    """Setup VM network"""

    device = 'eth%d' % did

    log.debug("Setting interfaces up for %s" % device)
    # Note: only remove all existing networks on first run.
    setup_vm_on_network(session, vm_ref, network_ref, device, wipe=(did == 0))

    log.debug("Static Manager Recs: %s" % sms)
    if sms and network_ref in sms.keys() and sms[network_ref]:
        static_manager = sms[network_ref]
        ip = static_manager.get_ip()
        log.debug("IP: %s Netmask: %s Gateway: %s" %
                  (ip.addr, ip.netmask, ip.gateway))

        droid_set_static(session, vm_ref, 'ipv4', device,
                         ip.addr, ip.netmask, ip.gateway)


def config_networks_for_droid_vm(session, vm_ref, network_refs, id_start=0, sms=None):
    """Setup VM networks"""

    log.debug("Setup vm %s on network" % vm_ref)

    i = id_start
    for network_ref in network_refs:
        config_network_for_droid_vm(session, vm_ref, network_ref, i, sms)
        i += 1


def shutdown_two_droid_vms(session, vm1_ref, vm2_ref):
    """Shutdown two VMs"""

    log.debug("Shutdown required VMs")
    try:
        run_xapi_async_tasks(session,
                             [lambda: session.xenapi.Async.VM.shutdown(vm1_ref),
                              lambda: session.xenapi.Async.VM.shutdown(vm2_ref)],
                             180)

    except TimeoutFunctionException, e:
        log.debug("Timed out while shutdowning VMs: %s" % e)


def start_two_droid_vms(session, host_master_ref, host_slave_ref, vm1_ref, vm2_ref):
    """Start two VMs"""

    log.debug("Starting required VMs")
    try:
        # Temporary setting time out to 3 mins to work around CA-146164.
        # The fix requires hotfixes, hence keeping this work-around.
        run_xapi_async_tasks(session,
                             [lambda: session.xenapi.Async.VM.start_on(vm1_ref,
                                                                       host_master_ref,
                                                                       False, False),
                              lambda: session.xenapi.Async.VM.start_on(vm2_ref,
                                                                       host_slave_ref,
                                                                       False, False)],
                             180)

    except TimeoutFunctionException, e:
        # Temporary ignore time out to start VM.
        # If VM failed to start, test will fail while checking IPs.
        log.debug("Timed out while starting VMs: %s" % e)
        log.debug("Async call timed out but VM may started properly. tests go on.")

    # Temp fix for establishing that a VM has fully booted before
    # continuing with executing commands against it.
    log.debug("Wait for IPs...")
    wait_for_all_ips(session, vm1_ref)
    wait_for_all_ips(session, vm2_ref)
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


def deploy_two_droid_vms(session, network_refs, sms=None):
    """A utility method for setting up two VMs, one on the primary host, and one on a slave host"""

    host_master_ref, host_slave_ref, vm1_ref, vm2_ref = import_two_droid_vms(
        session, network_refs, sms)
    config_networks_for_droid_vm(session, vm1_ref, network_refs, 0, sms)
    config_networks_for_droid_vm(session, vm2_ref, network_refs, 0, sms)
    start_two_droid_vms(session, host_master_ref,
                        host_slave_ref, vm1_ref, vm2_ref)

    return vm1_ref, vm2_ref


def deploy_two_droid_vms_for_sriov_test(session, vf_driver, network_refs, sms=None):
    """A utility method for setting up two VMs, one on the primary host for SR-IOV test network,
    and one on a slave host"""

    host_master_ref, host_slave_ref, vm1_ref, vm2_ref = import_two_droid_vms(
        session, network_refs, sms)

    # config management network
    config_network_for_droid_vm(session, vm1_ref, network_refs[1][0], 0, sms)
    config_network_for_droid_vm(session, vm2_ref, network_refs[0][0], 0, sms)
    start_two_droid_vms(session, host_master_ref,
                        host_slave_ref, vm1_ref, vm2_ref)

    args = {'vm_ref': vm1_ref,
            'username': 'root',
            'password': DEFAULT_PASSWORD}
    call_ack_plugin(session, 'disable_network_device_naming', args)

    # management network is ready then install VF driver on VM, reboot VM again
    args = {'vm_ref': vm1_ref,
            'username': 'root',
            'password': DEFAULT_PASSWORD,
            'package': vf_driver[1],
            'driver_name': vf_driver[0]}
    call_ack_plugin(session, 'deploy_vf_driver', args)

    shutdown_two_droid_vms(session, vm1_ref, vm2_ref)

    # config test networks
    config_networks_for_droid_vm(session, vm1_ref, network_refs[1][1:], 1, sms)
    config_networks_for_droid_vm(session, vm2_ref, network_refs[0][1:], 1, sms)
    start_two_droid_vms(session, host_master_ref,
                        host_slave_ref, vm1_ref, vm2_ref)

    return vm1_ref, vm2_ref


def droid_set_static(session, vm_ref, protocol, iface, ip, netmask, gw):
    args = {'vm_uuid': session.xenapi.VM.get_uuid(vm_ref),
            'protocol': protocol,
            'iface': iface,
            'ip': ip,
            'netmask': netmask,
            'gateway': gw}
    return call_ack_plugin(session, 'droid_set_static_conf', args)


class TimeoutFunction:
    """Wrapper class for providing a timemout for 
    the execution of a function"""

    def __init__(self, function, timeout, exception=''):
        self.timeout = timeout
        self.function = function
        self.exception = exception

    def handle_timeout(self, *args, **kwargs):
        raise TimeoutFunctionException(self.exception)

    def __call__(self, *args):
        old = signal.signal(signal.SIGALRM, self.handle_timeout)
        signal.alarm(self.timeout)
        try:
            result = self.function(*args)
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old)
        return result


def json_loads(json_data):
    def process_dict_keys(d):
        new_d = {}
        for key in d.iterkeys():
            new_key = str(key.replace(" ", "_"))
            new_d[new_key] = d[key]
        return new_d

    def process_values(item):
        if isinstance(item, unicode):
            item = str(item)
        elif isinstance(item, list):
            for elem in item:
                elem = process_values(elem)
        elif isinstance(item, dict):
            item = process_dict_keys(item)
            for key in item.iterkeys():
                item[key] = str(item[key])
        return item

    data = json.loads(json_data, object_hook=process_values)
    return [data] if isinstance(data, dict) else data


def call_ack_plugin(session, method, args={}, host=None, noJsonHook=False):
    if not host:
        host = get_pool_master(session)
    log.debug("About to call plugin '%s' on host '%s' with args '%s'" %
              (method, host, args))

    res = session.xenapi.host.call_plugin(host,
                                          'autocertkit',
                                          method,
                                          args)
    log.debug("Plugin Output: %s" % (
        "%s[...check plugin log for more]" % res[:1000] if res and len(res) > 1000 else res))
    return (json.loads(res) if noJsonHook else json_loads(res)) if res else None


def get_hw_offloads(session, device):
    """We want to call the XAPI plugin on the pool
    master to return the offload capabilites of a device."""

    if call_ack_plugin(session, 'get_kernel_version').startswith('2.6'):
        res = call_ack_plugin(session, 'get_hw_offloads_from_core',
                              {'eth_dev': device})
    else:
        res = call_ack_plugin(session, 'get_hw_offloads',
                              {'eth_dev': device})

    return res[0]


def get_dom0_iface_info(session, host_ref, device):
    res = call_ack_plugin(session, 'get_local_device_info',
                          {'device': device},
                          host=host_ref)

    device_dict = res[0]
    return Iface(device_dict)


def get_vm_device_mac(session, vm_ref, device):
    """For a specified VM, obtain the MAC address of the specified dev"""
    if session.xenapi.VM.get_is_control_domain(vm_ref):
        # Handle Dom0 Case
        log.debug("get_vm_device_mac: VM (%s) device (%s)" % (vm_ref,
                                                              device))
        host_ref = session.xenapi.VM.get_resident_on(vm_ref)
        iface = get_dom0_iface_info(session, host_ref, device)
        return iface.mac
    else:
        # Handle the VM case
        vifs = session.xenapi.VM.get_VIFs(vm_ref)
        for vif in vifs:
            vif_rec = session.xenapi.VIF.get_record(vif)
            if vif_rec['device'] == device.replace('eth', ''):
                return vif_rec['MAC']
        raise Exception("Error: could not find device '%s' for VM '%s'" %
                        (device, vm_ref))


def get_iface_statistics(session, vm_ref, iface):
    res = call_ack_plugin(session, 'get_iface_stats',
                          {'iface': iface,
                           'vm_ref': vm_ref})
    stats_dict = res[0]
    return IfaceStats(iface, stats_dict)


def set_hw_offload(session, device, offload, state):
    """Call the a XAPI plugin on the pool master to set
    the state of an offload path on/off"""
    log.debug("Device: %s - Set %s %s" % (device, offload, state))
    return call_ack_plugin(session, 'set_hw_offload',
                           {'eth_dev': device, 'offload': offload,
                            'state': state})


def set_nic_device_status(session, interface, status):
    """Function to set an ifconfig ethX interface up or down"""
    log.debug("Bringing %s network interface %s" % (status, interface))
    call_ack_plugin(session, 'set_nic_device_status',
                    {'device': interface, 'status': status})
    wait_for_linkstate(session, interface, status)
    time.sleep(5)


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


def get_system_info_hwinfo(session):
    return call_ack_plugin(session, 'get_system_info_hwinfo', noJsonHook=True)


def get_system_info_tabular(session):
    return call_ack_plugin(session, 'get_system_info_tabular')


def get_master_network_devices(session):
    nics = call_ack_plugin(session, 'get_network_devices')
    log.debug("Network Devices found on machine(Plugin): '%s'" % nics)

    # remove invalid keys of nic which violates xml, referring to
    # https://stackoverflow.com/questions/19677315/xml-tagname-starting-with-number-is-not-working
    for n in nics:
        for k in n.keys():
            if k and k[0].isdigit():
                n.pop(k)
                log.debug("Remove invalid key %s from %s" % (k, n['PCI_name']))

    hwinfo_devs = get_system_info_hwinfo(session)
    if hwinfo_devs:
        nics_hw = hwinfo_devs['nics']
        log.debug("Network Devices found on machine(hwinfo): '%s'" % nics_hw)
        for n in nics:
            for nh in nics_hw:
                if n['PCI_name'] == "0000:%s" % nh['device_bus_id']:
                    n.update(nh)
    return nics


def get_local_storage_info(session):
    """Returns info about the local storage devices"""
    devices = call_ack_plugin(session, 'get_local_storage_devices')
    log.debug("Local Storage Devices found on machine: '%s'" % devices)
    return devices


def _convertToValidXmlElementName(str1):
    if str1 and not str1[0].isalpha():
        str1 = "_" + str1
    str1 = str1.replace(":", "_")
    return str1


def _convertDictKeysToValidXmlTags(d):
    return {_convertToValidXmlElementName(k): d[k] for k in d}


def get_xs_info(session):
    """Returns a limited subset of info about the XenServer version"""
    master_ref = get_pool_master(session)
    info = session.xenapi.host.get_software_version(master_ref)
    return _convertDictKeysToValidXmlTags(info)


def _get_type_and_value(entry):
    """Parse dmidecode entry and return key/value pair"""
    r = {}
    for l in entry.split('\n'):
        s = l.split(':')
        if len(s) != 2:
            continue
        r[s[0].strip()] = s[1].strip()
    return r


def get_system_info(session):
    """Returns some information of system and bios."""

    rec = {}
    biosinfo = search_dmidecode(session, "BIOS Information")
    if biosinfo:
        entries = _get_type_and_value(biosinfo[0])
        if 'Vendor' in entries:
            rec['BIOS_vendor'] = entries['Vendor']
        if 'Version' in entries:
            rec['BIOS_version'] = entries['Version']
        if 'Release Date' in entries:
            rec['BIOS_release_date'] = entries['Release Date']
        if 'BIOS Revision' in entries:
            rec['BIOS_revision'] = entries['BIOS Revision']

    sysinfo = search_dmidecode(session, "System Information")
    if sysinfo:
        entries = _get_type_and_value(sysinfo[0])
        if 'Manufacturer' in entries:
            rec['system_manufacturer'] = entries['Manufacturer']
        if 'Product Name' in entries:
            rec['system_product_name'] = entries['Product Name']
        if 'Serial Number' in entries:
            rec['system_serial_number'] = entries['Serial Number']
        if 'UUID' in entries:
            rec['system_uuid'] = entries['UUID']
        if 'Version' in entries:
            rec['system_version'] = entries['Version']
        if 'Family' in entries:
            rec['system_family'] = entries['Family']

    chassisinfo = search_dmidecode(session, "Chassis Information")
    if chassisinfo:
        entries = _get_type_and_value(chassisinfo[0])
        if 'Type' in entries:
            rec['chassis_type'] = entries['Type']
        if 'Manufacturer' in entries:
            rec['chassis_manufacturer'] = entries['Manufacturer']

    return rec


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
            # get the class info
            print format(test_class.__doc__)
            print "%s: %s" % (bold('Prereqs'), test_class.required_config)
            sys.exit(0)
        elif len(arr) == 3 and ".".join(arr[:2]) == test_class_name:
            # get the method info
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
    import test_generators
    tg = test_generators.TestGenerator(
        'nonexistent_session', {}, 'nonexistent')
    return tg.get_test_classes()


def read_valid_lines(filename):
    """Utility function for returning alist of uncommented lines (as indicated by '#')."""
    comment_symbols = ['#']
    fh = open(filename, 'r')
    res = [line for line in [line.strip() for line in fh.readlines()]
           if len(line) > 0 and line[0] not in comment_symbols]
    fh.close()
    return res


def set_network_mtu(session, network_ref, MTU):
    """Utility function for setting a network's MTU. MTU should be a string"""
    session.xenapi.network.set_MTU(network_ref, str(MTU))
    pifs = session.xenapi.network.get_PIFs(network_ref)
    for pif in pifs:
        unplug_pif(session, pif)
        plug_pif(session, pif)


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
    """Wait until both hosts are up and live."""

    log.debug("Wait for hosts to come back online...")
    hosts = session.xenapi.host.get_all()
    num_hosts = len(hosts)
    log.debug("Total in %d hosts are being checked." % num_hosts)

    start = time.time()
    while not should_timeout(start, timeout):
        for host in hosts:
            rec = session.xenapi.host.get_record(host)
            hostname = session.xenapi.host.get_hostname(host)
            hostuuid = session.xenapi.host.get_uuid(host)
            if rec['enabled'] and \
                    session.xenapi.host_metrics.get_live(rec['metrics']):
                pif = get_management_interface(session, host)
                dev = session.xenapi.PIF.get_device(pif)
                try:
                    dom0 = _find_control_domain(session, host)
                    _get_control_domain_ip(session, dom0, dev)
                except:
                    log.debug("Host %s(%s) is up but not live yet." %
                              (hostname, hostuuid))
                    break
                else:
                    log.debug("Host %s(%s) is up and live." %
                              (hostname, hostuuid))
            else:
                log.debug("Host %s(%s) is not fully up yet." %
                          (hostname, hostuuid))
                break
        else:
            return
        time.sleep(2)

    raise Exception("Hosts(%s) failed to come back online" % hosts)


def get_ack_version(session, host=None):
    """Return the version string corresponding to the cert kit on a particular host"""
    try:
        return call_ack_plugin(session, 'get_ack_version', {}, host=host)
    except XenAPI.Failure, e:
        log.debug("Failed to execute ack plugin call means ACK is not installed.")
        return None


def combine_recs(rec1, rec2):
    """Utility function for combining two records into one."""
    rec = dict(rec1)
    for k, v in rec2.iteritems():
        if k in rec.keys():
            raise Exception(
                "Cannot combine these recs, and keys overalp (%s)" % k)
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
        log.debug("Checking for ping response from VM %s on interface %s at %s" % (
            vm_ref, interface, vm_ip))
        process = subprocess.Popen(call, stdout=subprocess.PIPE)
        stdout, stderr = process.communicate()
        response = str(stdout).strip()

        # Check for no packet loss. Note the space before '0%', this is
        # required.
        if " 0% packet loss" in response:
            log.debug("Ping response received from %s" % vm_ip)
            return response

        log.debug("No ping response")
        time.sleep(3)

    raise Exception("VM %s interface %s could not be reached in the given timeout" % (
        vm_ref, interface))


def valid_ping_response(ping_response, max_loss=0):

    if max_loss > 100:
        raise Exception("Error: cannot have a loss of > 100%!")

    regex = re.compile(r"(?P<loss>\d+)\% packet loss")
    match = regex.search(ping_response)
    if match:
        # We've matched the regex for the ping result, now we
        # check whether the number of packets lost is acceptable.
        loss = int(match.group('loss'))
        return loss <= max_loss
    else:
        # We did not match the ping output, therefore we cannot
        # validate the response.
        return False


@log_exceptions
def get_dmidecode_output(session):
    """ Build dmidecode information data structure from output of dmidecode. """
    binfo = call_ack_plugin(session, 'get_dmidecode_output')
    buf = ''
    dmidecode_output = []
    for line in binfo.split(os.linesep):
        if len(line.strip()) == 0:
            dmidecode_output.append(buf)
            buf = ''
        else:
            buf += line + os.linesep
    return dmidecode_output


@log_exceptions
def search_dmidecode(session, keyword):
    """ Search ttype or busid from ds """
    ds = get_dmidecode_output(session)
    found = []
    for info in ds:
        if keyword in info:
            found.append(info)

    return found
