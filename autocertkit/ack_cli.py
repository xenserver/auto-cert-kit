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
# @PRODUCT_VERSION@
# @BUILD_NUMBER@
import utils
import sys
import os
import ConfigParser

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
INSTALL_DIR = '/opt/xensource/packages/files/auto-cert-kit'


def get_xapi_session(config):
    # Future improvement, implement remote login. For now, just return local
    return utils.get_local_xapi_session()


def parse_cmd_args():
    parser = OptionParser(
        usage="%prog [options]", version="%prog @KIT_VERSION@")

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
    parser.add_option("-g", "--generate",
                      dest="generate",
                      action="store_const",
                      const=True,
                      default=False,
                      help="Generate the config file only. Do not run the tests yet.")
    parser.add_option("-l", "--list",
                      dest="list_tests",
                      action="store_const",
                      const=True,
                      default=False,
                      help="List all of the test methods")
    parser.add_option("-i", "--info",
                      dest="info",
                      help="Print out information about a specified test name.")
    parser.add_option("-m", "--mode",
                      dest="mode",
                      default="ALL",
                      help="Specify the type of certification you wish to perform. (ALL (default) | NET | LSTOR | CPU | OPS).")
    parser.add_option("-e", "--exclude",
                      dest="exclude",
                      action="append",
                      default=[],
                      help="Exclude one or multiple set of tests. (OVS | BRIDGE | LSTOR | CPU | OPS | CRASH).")
    parser.add_option("-n", "--netconf",
                      dest="netconf",
                      help="Specify the network config file.")
    # The option string is an extension, allowing users to specify KVPs
    # e.g. optionstr = "dhcp=True,key1=val1,..."
    parser.add_option("-o", "--option",
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

    if options.netconf:
        assert_file_exists(options.netconf, 'Network config')
        config['netconf'] = parse_netconf_file(options.netconf)
    else:
        raise utils.ArgumentError(
            "You must specify a network configuration file. %s" % options.mode)

    config['mode'] = options.mode
    config['exclude'] = options.exclude
    utils.log.debug("Test Mode: %s" % options.netconf)
    if options.list_tests:
        print_all_test_classes()

    if options.optionstr:
        kvp_rec = kvp_string_to_rec(options.optionstr)
        for k, v in kvp_rec.iteritems():
            config[k] = v

    # Check if files exist
    file_opts = [("vpx_dlvm_file", "VPX DLVM file")]
    for opt, label in file_opts:
        if opt in config.keys():
            assert_file_exists(os.path.join(INSTALL_DIR, config[opt]), label)

    for key, value in config['netconf'].iteritems():
        if key.startswith('eth'):
            vf_driver_pkg = value['vf_driver_pkg']
            if vf_driver_pkg:
                assert_file_exists(os.path.join(
                    INSTALL_DIR, vf_driver_pkg), "VF driver rpm package")

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
    """Parse network config file in ini format
    E.g.
        [eth0]
        network_id = 0
        vlan_ids = 200,204,240
        vf_driver_name = igbvf
        vf_driver_pkg = igbvf-2.3.9.6-1.x86_64.rpm
        max_vf_num = 8

        [static_0_200]
        ip_start = 192.168.0.2
        ip_end = 192.168.0.10
        netmask = 255.255.255.0
        gw = 192.168.0.1

        [static_management]
        # similar to static_0_200
    """
    utils.log.debug("Parse network config file: %s" % filename)

    cp = ConfigParser.ConfigParser()
    cp.read(filename)
    rec = {}
    for section in cp.sections():
        if section.startswith('eth'):
            # Ethernet Interface
            utils.log.debug("Ethernet Interface: '%s'" % section)

            # Network ID is a label of the physical network the adapter has been connected to
            # and should be uniform across all adapters.
            network_id = cp.get(section, 'network_id')
            utils.log.debug("Network IDs: '%s'" % network_id)
            try:
                network_id = int(network_id)
            except:
                raise utils.InvalidArgument('Network IDs for %s' % section, network_id,
                                            'should be integer')

            # Parse VLAN IDs
            vlan_ids = ""
            if cp.has_option(section, 'vlan_ids'):
                vlan_ids = cp.get(section, 'vlan_ids')
            utils.log.debug("VLAN IDs: '%s'" % vlan_ids)
            try:
                vlan_ids = [int(id.strip()) for id in vlan_ids.split(',')]
            except:
                raise utils.InvalidArgument('VLAN IDs for %s' % section, vlan_ids,
                                            'should be integer with comma as delimiter if multiple')
            # Ensure that the specified VLAN is valid
            for vlan_id in vlan_ids:
                if vlan_id > MAX_VLAN or vlan_id < MIN_VLAN:
                    raise utils.InvalidArgument('VLAN ID for %s' % section, vlan_id, '%d < x < %d' %
                                                (MIN_VLAN, MAX_VLAN))

            # VF driver info for SR-IOV test
            vf_driver_name = ""
            if cp.has_option(section, 'vf_driver_name'):
                vf_driver_name = cp.get(section, 'vf_driver_name')
            vf_driver_pkg = ""
            if cp.has_option(section, 'vf_driver_pkg'):
                vf_driver_pkg = cp.get(section, 'vf_driver_pkg')
            utils.log.debug("VF Driver Name: '%s'" % vf_driver_name)
            utils.log.debug("VF Driver Pkg: '%s'" % vf_driver_pkg)

            # User is able to specify maxinum VF number per PF to test
            max_vf_num = ""
            if cp.has_option(section, 'max_vf_num'):
                max_vf_num = cp.get(section, 'max_vf_num')
            if max_vf_num:
                try:
                    max_vf_num = int(max_vf_num)
                except:
                    raise utils.InvalidArgument('Maxinum VF number for %s' % section, max_vf_num,
                                                'should be integer')
                if max_vf_num <= 1:
                    raise utils.InvalidArgument('Maxinum VF number for %s' % section, max_vf_num,
                                                'should be greater than 1')
                max_vf_num = str(max_vf_num)
            utils.log.debug(
                "Maxinum VF number per PF to test: '%s'" % max_vf_num)

            rec[section] = {'network_id': network_id, 'vlan_ids': vlan_ids,
                            'vf_driver_name': vf_driver_name, 'vf_driver_pkg': vf_driver_pkg,
                            'max_vf_num': max_vf_num}
        elif section == "static_management":
            rec[section] = parse_static_config(cp, section)
        elif section.startswith('static'):
            # Definition of network properties (e.g. dhcp/static)
            arr = section.split('_')
            if len(arr) != 3:
                raise utils.InvalidArgument('static addressing section', section,
                                            'should be in format of "static_<network_id>_<vlan_id>"')
            net = arr[1]
            vlan = arr[2]
            if not unicode(net.strip()).isdecimal() or not unicode(vlan.strip()).isdecimal():
                raise utils.InvalidArgument('static addressing section', section,
                                            'should be valid network and/or vlan to determine')
            rec[section] = parse_static_config(cp, section)
        else:
            raise Exception("Error: Unknown section: '%s'" % section)

    return rec


def assert_file_exists(file_name, label):
    """Check whether a file exists, if it doesn't, raise an exception"""
    if not os.path.isfile(file_name):
        raise utils.ConfigFileNotFound(file_name, label)


def validate_param(value, possibles, arg_name):
    """Ensure that the provided value is one of values in the possibles list"""
    if value.upper() not in [string.upper() for string in possibles]:
        raise utils.InvalidArgument(arg_name, value, possibles)


def parse_static_config(configParser, section):
    """Parse a ini section specifying static networking config for droid VMs to use."""
    utils.log.debug("Read section '%s'" % section)
    config = {}
    for option in ['ip_start', 'ip_end', 'netmask', 'gw']:
        config[option] = configParser.get(section, option)
        utils.log.debug("Get option %s = '%s'" % (option, config[option]))
        if not config[option]:
            raise utils.InvalidArgument(
                option, config[option], "Should not be empty!")

    ip_s = utils.IPv4Addr(config['ip_start'], config['netmask'], config['gw'])
    ip_s.validate()
    ip_e = utils.IPv4Addr(config['ip_end'], config['netmask'], config['gw'])
    ip_e.validate()
    if ip_s.get_subnet_host()[1] >= ip_e.get_subnet_host()[1]:
        raise utils.InvalidArgument('ip_end', config['ip_end'],
                                    "Should be greater than 'ip_start' %s!" % config['ip_start'])

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
        dev = grp[0]  # we can use any of the devices in the group
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
    storage_devs = storage_interfaces_to_test(session)

    # Take an interface to use for non-networking tests
    if not len(ifs):
        raise Exception(
            "Error: in order to run these tests, you need at least one network defined.")

    xml_generators = list(XML_GENERATORS)

    # Support the loading of additional tests
    try:
        import ack_addons
        xml_generators.extend(ack_addons.XML_GENERATORS)
    except ImportError:
        utils.log.debug("No ack_addons module found.")

    for gen_cls in xml_generators:
        xml_generator = gen_cls(session, config, config[
                                'mode'], ifs, storage_devs)
        xml_generator.append_xml_config(doc, devices_node)

    fh = open(test_run_file, 'w')
    fh.write(doc.toxml())
    fh.close()


@utils.log_exceptions
def pre_flight_checks(session, config):
    """Check for some of the common problems"""

    # Check for a run in progress
    if check_for_process():
        raise Exception(
            "Error: An ACK process already exists on this host. Kill all running ACK processes and start the test again.")

    # Check for at least two hosts
    hosts = session.xenapi.host.get_all()
    if len(hosts) < 2:
        raise Exception(
            "Error: You need to have a pool of at least two hosts to run this kit. Only found %d." % (len(hosts)))

    for host in hosts:
        ver = utils.get_ack_version(session, host)
        if not ver:
            raise Exception(
                "Error: Both hosts need the Auto Cert Kit installed on them! The kit was not found on %s" % host)

    # Check that each host has some storage
    for host in hosts:
        avail_storage = utils.find_storage_for_host(session, host)
        if not avail_storage:
            raise Exception("Error: host '%s' has no available storage.")

    # Check that we have at least two network adaptors, on the same network
    recs = config['netconf']
    ifaces = {}
    for k, v in recs.iteritems():
        if k.startswith('eth'):
            ifaces[k] = v['network_id']

    utils.log.debug(
        "Network interfaces specified in config file: %s" % ifaces.keys())

    if 'singlenic' in config.keys() and config['singlenic'] == "true":
        utils.log.debug(
            "Skipping check for multiple networks, as only a single NIC is being tested")
        return

    # If less than 2 interfaces, raise an exception
    if len(ifaces.keys()) < 2:
        raise Exception("Error: the test kit needs at least 2 network interfaces to be defined in your network config file. Only %d were found: %s" % (
            len(ifaces.keys()), ifaces.keys()))

    # If less than 2 interfaces share the same network, raise an exception
    for k, v in ifaces.iteritems():
        if ifaces.values().count(v) < 2:
            raise Exception("Error: ethernet device %s on network %s is defined in the network config but does not have a matching partner. \
                Please review the nework configuration and minumum requirements of this kit." % (k, v))


def main(config, test_run_file):
    """Main routine - assess which tests should be run, and create
    output file"""

    session = get_xapi_session(config)

    # Ensure that all hosts in the pool have booted up.
    utils.wait_for_hosts(session)

    # Start Logger
    utils.init_ack_logging(session)

    utils.log.info("Options: %s" % config)

    # Pre checks before running tests
    pre_flight_checks(session, config)

    config['xs_version'] = utils.get_xenserver_version(session)
    config['xcp_version'] = utils.get_xcp_version(session)

    generate_test_config(session, config, test_run_file)

    if 'generate' in config:
        # Generate config file only
        utils.log.info("Test file generated")
        session.logout()
        return "OK"

    # cleanup in case previous run did not complete entirely
    if utils.pool_wide_cleanup(session):
        utils.reboot_normally(session)

    # Logout of XAPI session anyway - the test runner will create a new session
    # if needed. (We might only be generating).
    session.logout()

    # Kick off the testrunner
    utils.log.info("Starting Test Runner from ACK CLI.")
    test_file, output = test_runner.run_tests_from_file(test_run_file)


if __name__ == "__main__":
    # Parse Args
    config = parse_cmd_args()

    # Default config file
    test_run_file = 'test_run.conf'

    main(config, test_run_file)
