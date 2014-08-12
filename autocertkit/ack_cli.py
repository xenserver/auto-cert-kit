#!/usr/bin/python

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


"""CLI for generating auto cert kit configuration file"""
#@PRODUCT_VERSION@
#@BUILD_NUMBER@
import utils
import sys
import os
utils.configure_logging('auto-cert-kit')

import testbase
import inspect

import operator
import itertools
from test_generators import *
from status import check_for_process

import test_report
import test_runner
from optparse import OptionParser
from exceptions import *

MIN_VLAN = 0
MAX_VLAN = 4096

def get_xapi_session(config):
    #Future improvement, implement remote login. For now, just return local
    return utils.get_local_xapi_session()

def parse_cmd_args():
    parser = OptionParser(usage="%prog [options]", version="%prog @KIT_VERSION@")

    parser.add_option("-d", "--debug",
                      dest="debug",
                      action="store_const",
                      const=True,
                      default=False,
                      help="Run in debug mode, exit on failure")
    parser.add_option("-t", "--vlantag",
                      dest="vlan",
                      default="trunk",
                      help="Specify a VLAN tag ID for which your switches have been configured")
    parser.add_option("-g","--generate",
                      dest="generate",
                      action="store_const",
                      const=True,
                      default=False,
                      help="Generate the config file only. Do not run the tests yet.")
    parser.add_option("-l","--list",
                      dest="list_tests",
                      action="store_const",
                      const=True,
                      default=False,
                      help="List all of the test methods")
    parser.add_option("-i","--info",
                      dest="info",
                      help="Print out information about a specified test name.")
    parser.add_option("-m", "--mode",
                      dest="mode",
                      default="ALL",
                      help="Specify the type of certification you wish to perform. (ALL (default) | NET | LSTOR | CPU | OPS).")
    parser.add_option("-e","--exclude",
                      dest="exclude",
                      action="append",
                      default=[],
                      help="Exclude one or multiple set of tests. (OVS | BRIDGE | LSTOR | CPU | OPS).")
    parser.add_option("-n","--netconf",
                      dest="netconf",
                      help="Specify the network config file.")
    # The option string is an extension, allowing users to specify KVPs
    # e.g. optionstr = "dhcp=True,key1=val1,..."
    parser.add_option("-o","--option",
                      dest="optionstr",
                      help="Specify extra options.")


    (options, _) = parser.parse_args()

    config = {}


    config['debug'] = options.debug

    if options.vlan:
        config['vlan_id'] = options.vlan

    if options.generate:
        config['generate'] = True

    if options.info:
        print_documentation(options.info)

    validate_param(options.mode, ['ALL', 'NET', 'LSTOR', 'CPU', 'OPS'], "Run Mode")

    if options.netconf:
        assert_file_exists(options.netconf, 'Network config')
        config['netconf'] = parse_netconf_file(options.netconf)
    else:
        raise utils.ArgumentError("You must specify a network configuration file. %s" % options.mode)

    config['mode'] = options.mode
    config['exclude'] = options.exclude
    utils.log.debug("Test Mode: %s" % options.netconf)
    if options.list_tests:
        print_all_test_classes()

    if options.optionstr:
        kvp_rec = kvp_string_to_rec(options.optionstr)
        for k, v in kvp_rec.iteritems():
            config[k] = v

    return config

def kvp_string_to_rec(string):
    """Take an input string 'a=b,c=d,e=f' and return the record
    {'a':'b','c':'d','e':'f'}"""
    rec = {}
    for kvp in string.split(','):
        arr = kvp.split('=')
        if len(arr) > 2:
            raise Exception("Cannot convert %s to KVP" % string)
        rec[arr[0]] = arr[1]
    return rec

def parse_netconf_file(filename):

    arrs = utils.read_valid_lines(filename)
    utils.log.debug("netconf_file: '%s'" % arrs)
    rec = {}
    for arr in arrs:

        if arr.count('=') != 1:
            raise Exception("Error: format of netconf file should be 'key = value'")
        
        key, value = [items.strip() for items in arr.split('=')]

        if key.startswith('eth'):
            # Each line is in the format:
            # ethX = 3,[235,236,237]
            csv = [v.strip() for v in value.split(',')]

            # Ethernet Interface
            utils.log.debug("Ethernet Interface: '%s'" % key)

            # Network ID is a label of the physical network the adapter has been connected to
            # and should be uniform across all adapters.
            utils.log.debug("Network IDs: '%s'" % csv[0])
            network_id = int(csv[0])

            #Parse VLAN IDs
            try:
                # Extract bracketed substring
                vlan_str = arr[arr.index('[')+1:arr.index(']')]
                # Convert values to integers
                vlan_ids = [int(x) for x in vlan_str.split(',')]
                # Ensure that the specified VLAN is valid
                for vlan_id in vlan_ids:        
                    if vlan_id > MAX_VLAN or vlan_id < MIN_VLAN:
                        raise utils.InvalidArgument('VLAN ID for %s' % arr[0], vlan_id, '%d < x < %d' %
                                                    (MIN_VLAN, MAX_VLAN))  
            except ValueError:
                raise utils.InvalidArgument('VLAN IDs', vlan_str, '%d < x < %d: x = INT' %
                                            (MIN_VLAN, MAX_VLAN))

            rec[key] = {'network_id': network_id, 'vlan_ids': vlan_ids}

        elif key.startswith('static'):
            # Definition of network properties (e.g. dhcp/static)
            arr = key.split('_')
            if len(arr) != 3:
                raise Exception("Error: invalid argument %s" % arr)
            net = arr[1]
            vlan = arr[2]
            if unicode(net.strip()).isdecimal() and unicode(vlan.strip()).isdecimal():
                rec[key] = parse_static_config(value)
            else:
                raise Exception("Error: unable to determine network and/or vlan from '%s'" % key)

        else:
            raise Exception("Error: unable to parse line: '%s'" % arr)
                        

    return rec

def assert_file_exists(file_name, label):
    """Check whether a file exists, if it doesn't, raise an exception"""
    if not os.path.isfile(file_name):
        raise utils.ConfigFileNotFound(file_name, label)

def validate_param(value, possibles, arg_name):
    """Ensure that the provided value is one of values in the possibles list"""
    if value.upper() not in [string.upper() for string in possibles]:
        raise utils.InvalidArgument(arg_name, value, possibles)

def parse_static_config(string):
    """Parse a string specifying static networking config for droid VMs to use.
    The format should be ip_start,ip_end,netmask,gateway."""
    arr = string.split(',')
    
    if len(arr) != 4:
        raise Exception("The static config string supplied was invalid. It should be of the form: ip_start,ip_end,netmask,gateway. Actually '%s'" % string)

    config = {}
    
    def copy(label, pos):
        config[label] = arr[pos].strip()
    
    copy('ip_start', 0)
    copy('ip_end',1)
    copy('netmask',2)
    copy('gw',3)

    return config

def network_interfaces_to_test(session, config):
    """Return a list of all the ethernet devices that must be tested by the
    auto cert kit. In turn, each device must be the 'primary' interface,
    upon which we run our cert tests."""

    # Extract from netconf the network interfaces that the user
    # has specified.
    ifaces_to_test = [iface.strip() for iface in config['netconf'].keys() 
                      if iface.startswith('eth')]

    devices = utils.get_master_network_devices(session)

    # Filter the list of devices available on the master by the interfaces
    # specified by the caller in their netconf file.
    devices_to_test = [dev for dev in devices 
                      if dev['Kernel_name'] in ifaces_to_test]
    
    device_groups_list = []
    for key, items in itertools.groupby(devices_to_test, operator.itemgetter('PCI_id')):
        device_groups_list.append(list(items))

    ifaces = []
    for grp in device_groups_list:
        dev = grp[0] #we can use any of the devices in the group
        ifaces.append(dev['Kernel_name']) 
    return ifaces

def storage_interfaces_to_test(session):
    """Return a list of all storage interface devices that connected to local
    disks and must be tested by the auto cert kit."""

    def comp_key(src, dst, key):
        return key in src and key in dst and src[key] == dst[key]

    # Get all interfaces that has a disk connected.
    devices = utils.get_local_storage_info(session)

    # Some devices, which can have multiple disks, only need to be tested once.
    devices_to_test = []
    for device in devices:
        for existing in devices_to_test:
            if comp_key(device, existing, 'vendor') and \
                comp_key(device, existing, 'driver') and \
                comp_key(device, existing, 'subclass') and \
                comp_key(device, existing, 'class'):
                break
            if comp_key(device, existing, 'PCI_id'):
                break
        else:
            devices_to_test.append(device)

    return devices_to_test


def generate_test_config(session, config, test_run_file):
    """Enumerate hardware on machine and setup test config file"""

    doc = minidom.Document()

    kit_info_rec = {'version': '@KIT_VERSION@', 'build': '@BUILD_NUMBER@',
                    'product_version': '@PRODUCT_VERSION@'}

    root_node = doc.createElement('automated_certification_kit')
    utils.set_dict_attributes(root_node, kit_info_rec)
    doc.appendChild(root_node)

    global_config_node = doc.createElement('global_config')
    utils.set_dict_attributes(global_config_node, config)
    root_node.appendChild(global_config_node)

    # Create the XML node under which, each device we are testing
    # is located. 

    devices_node = doc.createElement('devices')
    root_node.appendChild(devices_node)

    # Based on the mode of operation, generate the particular tests
    # that the user would like to run.
    ifs = network_interfaces_to_test(session, config)
    if config['mode'] == 'ALL' or config['mode'] == 'NET':
        for iface in ifs:
            print "iface: %s" % iface
            natg = NetworkAdapterTestGenerator(session, config, iface)
            natg.append_xml_config(doc, devices_node)

    # Take an interface to use for non-networking tests
    if not len(ifs):
        raise Exception("Error: in order to run these tests, you need at least one network defined.")

    if config['mode'] == 'ALL' or config['mode'] == 'CPU':
        cputg = ProcessorTestGenerator(session, config)
        cputg.append_xml_config(doc, devices_node)

    if config['mode'] == 'ALL' or config['mode'] == 'LSTOR':
        for device in storage_interfaces_to_test(session):
            lstg = StorageTestGenerator(session, config, device)
            lstg.append_xml_config(doc, devices_node)

    if config['mode'] == 'ALL' or config['mode'] == 'OPS':
        optg = OperationsTestGenerator(session, config)
        optg.append_xml_config(doc, devices_node)

    fh = open(test_run_file, 'w')
    fh.write(doc.toxml())
    fh.close()

@utils.log_exceptions
def pre_flight_checks(session, config):
    """Check for some of the common problems"""
    
    #Check for a run in progress
    if check_for_process():
        raise Exception("Error: An ACK process already exists on this host. Kill all running ACK processes and start the test again.")
    
    #Check for at least two hosts
    hosts = session.xenapi.host.get_all()
    if len(hosts) < 2:
        raise Exception("Error: You need to have a pool of at least two hosts to run this kit. Only found %d." % (len(hosts)))

    for host in hosts:
        ver = utils.get_ack_version(session, host)
        if not ver:
            raise Exception("Error: Both hosts need the Auto Cert Kit installed on them! The kit was not found on %s" % host)

    # Check that each host has some storage
    for host in hosts:
       avail_storage = utils.find_storage_for_host(session, host)
       if not avail_storage:
           raise Exception("Error: host '%s' has no available storage.") 

    #Check that we have at least two network adaptors, on the same network
    recs = config['netconf']
    ifaces = {}
    for k, v in recs.iteritems():
        if k.startswith('eth'):
            ifaces[k] = v['network_id']
    
    utils.log.debug("Network interfaces specified in config file: %s" % ifaces.keys())

    if 'singlenic' in config.keys() and config['singlenic'] == "true":
        utils.log.debug("Skipping check for multiple networks, as only a single NIC is being tested")
        return

    #If less than 2 interfaces, raise an exception
    if len(ifaces.keys()) < 2:
        raise Exception("Error: the test kit needs at least 2 network interfaces to be defined in your network config file. Only %d were found: %s" % (len(ifaces.keys()), ifaces.keys()))

    #If less than 2 interfaces share the same network, raise an exception
    for k, v in ifaces.iteritems():
        if ifaces.values().count(v) < 2:
            raise Exception("Error: ethernet device %s on network %s is defined in the network config but does not have a matching partner. \
                Please review the nework configuration and minumum requirements of this kit." % (k, v))
    
@utils.log_exceptions
def main(config, test_run_file):
    """Main routine - assess which tests should be run, and create
    output file"""
    
    session = get_xapi_session(config)

    # Run log rotate before ACK produces any log.
    for host in session.xenapi.host.get_all():
        res = session.xenapi.host.call_plugin(host, 
                                    'autocertkit',
                                    'run_ack_logrotate', 
                                    {})
    # logger can be broken due to os file handler.
    utils.log = None
    utils.log = utils.configure_logging('auto-cert-kit')

    pre_flight_checks(session, config)

    config['xs_version'] = utils.get_xenserver_version(session)

    generate_test_config(session, config, test_run_file)
    # Logout of XAPI session anyway - the test runner will create a new session
    # if needed. (We might only be generating).
    session.logout()

    if 'generate' in config:
        #Generate config file only
        utils.log.info("Test file generated")
        return "OK"

    #Kick off the testrunner
    test_file, output = test_runner.run_tests_from_file(test_run_file)

if __name__ == "__main__":
    config = parse_cmd_args()

    #Default config file
    test_run_file = 'test_run.conf'

    main(config, test_run_file)
