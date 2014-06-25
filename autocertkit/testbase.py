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

"""Module for base test clasess from which test cases are derived"""

import traceback
import re
import signal
from utils import *
log = get_logger('auto-cert-kit')

class TestClass(object):
    """The base test class for defining attributes
    and methods that all other test classes must have
    or override"""

    config = {}
    collects = []
    static_managers = {}
    tags = []
    caps = [REQ_CAP]
    order = 1
    required = True
    required_config = []
    session = None
    base_tag = "Base"
    XS = ["> 5.6"]

    def __init__(self, session, config):
        """The constructor method.
        We expect to be passed a dictionary object containing
        global config used by each test case"""
        self.config = config
        self.session = session
        #Take a copy of the tag list and then append.
        self.tags = list(self.tags)
        self.tags.append(self.base_tag)
        self.extra_init()

    def get_tags(self):
        return self.tags

    def extra_init(self):
        """Can be overriden by subclasses to perform
        extra initialisation"""
        # Make sure we only run this on test run.
        if 'device_config' in self.config.keys():
            self.generate_static_net_conf()        

    def host_setup(self):
        """Method for running setup commands on a host
        before executing the tests. This may include
        operations that require a reboot. The test runner
        will handle re-executing the current test case
        when booting has finished"""
        return

    def run(self, debug=False, test_name=None):
        """Method for running all the tests in a class"""
        self.check_prerequisites()
        self.host_setup()
        results = []
        tests = self.list_tests()
        if test_name:
            arr = test_name.split('.')
            test_name = arr[len(arr)-1]
            log.debug("Test Selected = %s" % test_name)
        for test in tests:
            if test_name and test_name != test:
                continue

            # This assumes that we do not keep IPs across individual tests
            for vlan, sm in self.static_managers.iteritems():
                sm.release_all()

            # Release Alarm signal to prevent handled signal from previous test
            # interrupts this test. When there is no SIG_ALRM, this does nothing.
            signal.alarm(0)

            # Ensure that we cleanup before running tests, in case
            # the system has been left in a failed state. 
            pool_wide_cleanup(self.session)
            rec = {}
            try:
                log.debug("******** %s.%s ********" % (self.__class__.__name__, str(test)))
                res = getattr(self, test)(self.session)

                # If test executed without failure it can be either skipped or passed.
                if 'skipped' in res and res['skipped']:
                    rec['result'] = 'skip'
                    if 'warning' in res:
                        rec['warning'] = res['warning']
                else:
                    rec['result'] = 'pass'

                def copy_field(rec, res, field):
                    if field in res:
                        rec[field] = res[field]
                    else:
                        rec[field] = ""
                
                copy_field(rec, res, 'info')
                copy_field(rec, res, 'data')
                copy_field(rec, res, 'config')

            except Exception, e:
                traceb = traceback.format_exc()
                rec['result'] = 'fail'
                rec['traceback'] = traceb
                rec['exception'] = str(e)
                log.error("Test Case Failure: %s" % str(test))
                log.debug(traceb)
                if debug:
                    log.debug("Running in debug mode - exiting due to failure: %s" % str(e))
                    sys.exit(0)
            except:
                traceb = traceback.format_exc()
                exception = True
                rec['result'] = 'fail'
                rec['trackeback'] = traceb
                rec['exception'] = "Unexpected error: %s" % sys.exc_info()[0]
                log.debug(traceb)  
                if debug:
                    log.debug("Running in debug mode - exiting due to failure: %s" % sys.exc_info()[0])
                    sys.exit(0)

            log.debug("Test case %s: %s.%s" % (rec['result'], self.__class__.__name__, test))
            rec['test_name'] = "%s.%s" % (self.__class__.__name__, test)
            results.append(rec)
            pool_wide_cleanup(self.session)
        return results

    def check_prerequisites(self):
        """Check that the class has met it's prerequisites
        this is achieved by ensuring that for all 'required_config'
        keys, an entry is found in the config dict object"""

        for tag in self.required_config:
            log.debug("Checking for %s" % tag)
            if tag not in self.config or not self.config[tag]:
                raise Exception("Prerequisite '%s' has not been passed to this object" % tag)
            else:
                log.debug("Tag %s: %s" % (tag, self.config[tag]))

        xs_version = get_xenserver_version(self.session)
        for expr in self.XS:
            if not eval_expr(expr, xs_version):
                raise Exception("Could not run test due to XenServer version constraints:" +
                                " %s" % self.XS)

    def list_tests(self):
        """Return a list of tests contained within this class"""
        method_list = [method for method in dir(self) 
                      if callable(getattr(self,method)) 
                      and method.startswith('test')]
        return method_list

    def is_required(self):
        """Returns True by default, false if the test is optional"""
        return self.required

    def get_required_config(self):
        """Returns a list of parameters required for running
        the test cases with this class"""
        return self.required_config

    def generate_static_net_conf(self):
        log.debug("Config: %s" % self.config)
        netconf = self.get_netconf()
        log.debug("Netconf: %s" % netconf)
        netid_rec = {}
        for iface, rec in netconf.iteritems():
            if iface.startswith('eth'):
                log.debug("Rec: %s" % rec)
                nid = rec['network_id']

                # Required for initialisation
                if nid not in netid_rec:
                    netid_rec[nid] = []

                # Append interface on that network id
                netid_rec[nid].append(iface)

        res = {}
        regex = re.compile(r'static_(?P<netid>\d+)_(?P<vlan>\d+)')

        # Iterate through the network config structure to 
        # see if we have any static managers to initialise.
        for k, v in self.get_netconf().iteritems():
            # We only care about vlans on the physical network ID this test is running on

            match = regex.search(k)
            if match:
                network_id = int(match.group('netid'))
                vlan = match.group('vlan')
                log.debug("Static Config Record for Netid %d and Vlan %s" % \
                            (network_id, vlan))
                sm = StaticIPManager(v)

                # We must assign this static manager to all of the network references
                # which have the netid that has been specified.
                if network_id in netid_rec.keys():    
                    for iface in netid_rec[network_id]:
                        log.debug("Create static config for %s (%s)" % (iface, vlan))
                        key_name = "%s_%s" % (iface, vlan)
                        assert(key_name not in res.keys())
                        res[key_name] = sm
                        log.debug("Added static conf for '%s'" % key_name)

        
        self.static_managers = res
        log.debug("Static Managers Created: %s" % self.static_managers)

    def get_static_manager(self, network_ref, vlan='0'):
        """By default, return the zero'th VLAN static ip manager
        if it exists, otherwise just return None."""
        log.debug("get_static_manager: %s %s" % (network_ref, vlan))
        log.debug("All static recs: %s" % self.static_managers)

        devices = get_physical_devices_by_network(self.session, network_ref)

        # Note: we expect two devices for the case where we have created
        # a bond between two PIFs.
        if len(devices) > 2:
            raise Exception("Error: more than two devices " \
                            + "for network %s: %s" % (network_ref, devices))

        # In the case of a bond, we do not mind which device is used.
        iface = devices.pop()
    
        key = "%s_%s" % (iface, vlan)
        if key in self.static_managers.keys():
            return self.static_managers[key]
        else:
            return None

    def get_vlans(self, iface):
        """ For a specified ethernet interface, return the list of 
        VLANs that the user has declared to be in operation."""
        netconf = eval(self.config['netconf'])
        if iface not in netconf:
            raise Exception("The interface %s has not been defined in the network config file. (%s)" %
                            (iface, netconf))
        return netconf[iface]['vlan_ids']

    def get_netconf(self):
        """Return the network config dictionary, as provided by the user"""
        return eval(self.config['netconf'])

    def singlenicmode(self):
        return 'singlenic' in self.config.keys() and self.config['singlenic'] == 'true'

    def get_equivalent_devices(self):
        """Return a list of interfaces presented by devices with the same PCI ID as
        the one currently being tested by the testkit"""

        equiv_ifaces = intersection(get_equivalent_devices(self.session,
                                                           self.config['device_config']),
                                                           self.get_netconf().keys())

        log.debug("Equivalent devices for %s: %s" % (self.config['device_config']['Kernel_name'],
                                                     equiv_ifaces))
        return equiv_ifaces

    def get_pifs_to_use(self):
        equiv_devs = self.get_equivalent_devices()
        try:
            return filter_pif_devices(self.session, equiv_devs)
        except Exception, e:
            log.error("Caught Exception - may be OK if running in single NIC mode.")
            log.error("Exception Occurred: %s" % str(e))
            if self.singlenicmode():
                return equiv_devs
            else:
                raise e

    def get_networks(self):
        """Take in a list of available devices to use for testing
        and return a list of network references."""

        device_list = self.get_equivalent_devices()

        if self.singlenicmode():
            devices = device_list
        else:
            #Get no management ethernet devices
            devices = filter_pif_devices(self.session, device_list)

        results = []
        for device in devices:
            #Array access exception would be raised by filter_pif_devices
            pifs = get_pifs_by_device(self.session, device) 

            #Assumption that two PIFs are on the same network
            network_ref = self.session.xenapi.PIF.get_network(pifs[0])
            if len(pifs) > 1:
                for pif in pifs[1:]:
                    if self.session.xenapi.PIF.get_network(pif) != network_ref:
                        raise Exception("Assumption that identical devices " + 
                                        "in a pool are attached to the same " + 
                                        "network is invalid!")
            results.append(network_ref)

        #Raise an exception if no networks have been found
        if not len(results):
            raise Exception("No non-management networks have been found")

        return results

class NetworkTestClass(TestClass):
    """Sub class for Network Tests"""
    base_tag = 'NA'
    network_backend = 'vswitch'
    num_ips_required = 0
    
    def host_setup(self):
        """Overload setup function. Setup networking backend"""
        master_ref = get_pool_master(self.session)
    
        host_refs = self.session.xenapi.host.get_all()

        for host_ref in host_refs:
            oc = self.session.xenapi.host.get_other_config(host_ref)
            default_routes_key = 'default_routes'
            if default_routes_key not in oc.keys():
                routes = get_network_routes(self.session, host_ref)
                route_recs = [route.get_record() for route in routes]
                oc[default_routes_key] = str(route_recs)
                self.session.xenapi.host.set_other_config(host_ref, oc)
    
        def plugin_call(method, args):
            return self.session.xenapi.host.call_plugin(master_ref,
                                                        'autocertkit',
                                                        method,
                                                        args)
        
        backend = plugin_call('get_network_backend', {})
        log.debug("Current network backend: %s" % backend)
        log.debug("self.network_backend %s" % self.network_backend)
        if self.network_backend == 'vswitch' and backend == 'bridge':
            #Switch backend to vswitch
            plugin_call('set_network_backend_pool', {'backend': 'openvswitch'})
            host_reboot(self.session)
        elif self.network_backend == 'bridge' and backend == 'openvswitch':
            #Switch backend to bridge
            plugin_call('set_network_backend_pool', {'backend': 'bridge'})
            host_reboot(self.session)
        #Nothing to do, just return
        return

    def get_bondable_ifaces(self, iface):
        """ Given a particular interface, return a list of other network
        interfaces which have been defined as being on the same physical L2 network."""
        netconf = self.get_netconf()
        phy_id = netconf[iface]['network_id']

        log.debug("NetConf: '%s'" % netconf)
        # Construct a list of interface names who have the same physical ID
        # as the provided interface.

        blist = intersection([k for k, v in netconf.iteritems() if k.startswith('eth') and
                              v['network_id'] == phy_id],
                          netconf.keys())

        # Need to remove any occurances of the given interface, as we can't bond
        # with ourselves.

        while blist.count(iface) != 0:
            blist.remove(iface)

        return blist

    def get_primary_bond_iface(self):
        """For the device currently being tested, return all the interface which are equivalent,
        and can be bonded"""
        res = []

        # Only return interfaces which have more than bondable interface
        for iface in self.get_equivalent_devices():
            if self.get_bondable_ifaces(iface):
                res.append(iface)
                
        return res

class LocalStorageTestClass(TestClass):
    """Sub class for storage tests"""
    base_tag = 'LS'

class CPUTestClass(TestClass):
    """Sub class for CPU tests"""
    base_tag = 'CPU'

class OperationsTestClass(TestClass):
    """Sub class for Operations tests"""
    base_tag = 'OP'

