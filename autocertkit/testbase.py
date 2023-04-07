# Copyright (c) 2005-2022 Citrix Systems Inc.
# Copyright (c) 2022-12-01 Cloud Software Group Holdings, Inc.
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
    XS_REQ = ">= 6.0"
    XCP_REQ = ">= 1.0"
    REQUIRED_FOR = None

    def __init__(self, session, config):
        """The constructor method.
        We expect to be passed a dictionary object containing
        global config used by each test case"""
        self.config = config
        self.session = session
        # Take a copy of the tag list and then append.
        self.tags = list(self.tags)
        self.tags.append(self.base_tag)
        self.extra_init()

    def get_tags(self):
        return self.tags

    def extra_init(self):
        """Can be overriden by subclasses to perform
        extra initialisation"""
        # Make sure we only run this on test run.
        if 'device_config' in list(self.config.keys()):
            self.generate_static_net_conf()

    def host_setup(self):
        """Method for running setup commands on a host
        before executing the tests. This may include
        operations that require a reboot. The test runner
        will handle re-executing the current test case
        when booting has finished"""
        pass

    def run(self, debug=False, test_name=None):
        """Method for running all the tests in a class"""
        self.check_prerequisites()
        self.host_setup()

        results = []

        tests = self.list_tests()
        if test_name:
            arr = test_name.split('.')
            test_name = arr[len(arr) - 1]
            log.debug("Test Selected = %s" % test_name)

        for test in tests:
            if test_name and test_name != test:
                continue

            # This assumes that we do not keep IPs across individual tests
            for vlan, sm in self.static_managers.items():
                sm.release_all()

            # Release Alarm signal to prevent handled signal from previous test
            # interrupts this test. When there is no SIG_ALRM, this does
            # nothing.
            signal.alarm(0)

            rec = {}
            self.run_test(test, debug, rec)

            self.cleanup_test(debug, rec)

            log.debug("Test case %s, %s: %s.%s" %
                      (rec['result'], rec['status'], self.__class__.__name__, test))
            rec['test_name'] = "%s.%s" % (self.__class__.__name__, test)
            results.append(rec)

        return results

    def copy_field(self, rec, res, field, keep_tag=True):
        if field in res:
            rec[field] = res[field]
        elif keep_tag:
            rec[field] = ""

    def run_test(self, test, debug, rec):
        try:
            log.debug("******** %s.%s ********" % (
                self.__class__.__name__, test))

            init_context()

            res = getattr(self, test)(self.session)
            """
            Critical key and value in res:
                'status': 'init'    initial status before running
                          'running' test still running
                          'done',   test finished
                'result': 'skip'    needless to run
                          'pass'    test OK
                          'fail'    test failed (with Exception occurs)
                'control': any private data of test itself.
                'superior': return common info to test runner from test, 
                            test runner will handle and take general action, then remove it,
                            so it won't be saved into xml file.
                            currently it's used for rebooting hosts only.
            """

            log.debug("test return: %s" % res)

            if 'superior' in res:
                rec['status'] = 'running'
                rec['result'] = 'NULL'
                rec['superior'] = res['superior']
            else:
                rec['status'] = 'done'
                rec['result'] = 'pass'

            self.copy_field(rec, res, 'control', False)
            self.copy_field(rec, res, 'info')
            self.copy_field(rec, res, 'data')
            self.copy_field(rec, res, 'config')
            self.copy_field(rec, res, 'reason', False)
            self.copy_field(rec, res, 'warning', False)

        except Exception as e:
            traceb = traceback.format_exc()
            rec['status'] = 'done'
            rec['result'] = 'fail'
            rec['traceback'] = traceb
            rec['exception'] = str(e)
            log.error("Test Case Failure: %s" % str(test))
            log.debug(traceb)
            if debug:
                log.debug(
                    "Running in debug mode - exiting due to Exception class: %s" % str(e))
                sys.exit(0)
        except:
            traceb = traceback.format_exc()
            rec['status'] = 'done'
            rec['result'] = 'fail'
            rec['trackeback'] = traceb
            rec['exception'] = "Unexpected error: %s" % sys.exc_info()[0]
            log.debug(traceb)
            if debug:
                log.debug(
                    "Running in debug mode - exiting due to exception: %s" % sys.exc_info()[0])
                sys.exit(0)

    def cleanup_test(self, debug, rec):
        # cleanup occurs only when current test really done
        if rec['status'] != 'done':
            return

        try:
            need_reboot = pool_wide_cleanup(self.session)
        except:
            traceb = traceback.format_exc()
            log.debug(traceb)
            if debug:
                log.debug(
                    "Running in debug mode - exiting due to exception when cleanup: %s" % sys.exc_info()[0])
                sys.exit(0)

            log.debug("The general cleanup is failed")
            # reset test result
            if rec['result'] == 'pass':
                rec['result'] = 'fail'
                rec['trackeback'] = traceb
                rec['exception'] = "Unexpected error: %s" % \
                                   sys.exc_info()[0]
        else:
            # If test done normally then noneed reboot even if cleanup requires, that indicates
            # test itself should handle reboot requirement as one test step
            # If test is done by exception and cleanup requires reboot then ask runner to reboot
            if rec['result'] == 'pass' and need_reboot:
                log.debug(
                    "Warning: test should handle reboot requirement")
            elif rec['result'] == 'fail' and need_reboot:
                rec['superior'] = 'reboot'
                log.debug(
                    "Ask for hosts reboot because current test did not finish normally")

    # set result dict using below functions in TestClass
    def set_control(self, rec, value):
        rec['control'] = str(value)

    def set_info(self, rec, info):
        rec['info'] = info

    def set_data(self, rec, data):
        rec['data'] = data

    def set_config(self, rec, config):
        rec['config'] = config

    def set_reason(self, rec, reason):
        rec['reason'] = reason

    def set_warning(self, rec, warning):
        rec['warning'] = warning

    def set_test_name(self, rec, test_name):
        rec['test_name'] = test_name

    def set_superior(self, rec, superior):
        rec['superior'] = superior

    def unset_superior(self, rec):
        rec.pop("superior", None)

    def check_prerequisites(self):
        """Check that the class has met it's prerequisites
        this is achieved by ensuring that for all 'required_config'
        keys, an entry is found in the config dict object"""

        for tag in self.required_config:
            log.debug("Checking for %s" % tag)
            if tag not in self.config or not self.config[tag]:
                raise Exception(
                    "Prerequisite '%s' has not been passed to this object" % tag)
            else:
                log.debug("Tag %s: %s" % (tag, self.config[tag]))

        xs_version = get_xenserver_version(self.session)
        if eval_expr(self.XS_REQ, xs_version):
            return
        xcp_version = get_xcp_version(self.session)
        if eval_expr(self.XCP_REQ, xcp_version):
            return

        raise Exception("versions do not meet requirements.")

    def list_tests(self):
        """Return a list of tests contained within this class"""
        method_list = [method for method in dir(self)
                       if callable(getattr(self, method))
                       and method.startswith('test')]
        return method_list

    def is_required(self):
        """Returns True by default, false if the test is optional"""
        return self.required

    def get_required_config(self):
        """Returns a list of parameters required for running
        the test cases with this class"""
        return self.required_config

    def generate_static_net_conf_common(self, netid_rec, res):
        regex = re.compile(r'static_(?P<netid>\d+)_(?P<vlan>\d+)')  # NOSONAR

        # Iterate through the network config structure to
        # see if we have any static managers to initialise.
        for k, v in self.get_netconf().items():
            # We only care about vlans on the physical network ID this test is
            # running on

            match = regex.search(k)
            if match:
                network_id = int(match.group('netid'))
                vlan = match.group('vlan')
                log.debug("Static Config Record for Netid %d and Vlan %s" %
                          (network_id, vlan))
                sm = StaticIPManager(v)

                # We must assign this static manager to all of the network references
                # which have the netid that has been specified.
                if network_id in list(netid_rec.keys()):
                    for iface in netid_rec[network_id]:
                        log.debug("Create static config for %s (%s)" %
                                  (iface, vlan))
                        key_name = "%s_%s" % (iface, vlan)
                        assert key_name not in list(res.keys()), \
                            "Duplicate static IP addressing specified for %s (%s)" % (
                                iface, vlan)
                        res[key_name] = sm
                        log.debug("Added static conf for '%s'" % key_name)

    def generate_static_net_conf(self):
        log.debug("Config: %s" % self.config)
        netconf = self.get_netconf()
        log.debug("Netconf: %s" % netconf)
        netid_rec = {}
        for iface, rec in netconf.items():
            if iface.startswith('eth'):
                log.debug("iface: %s Rec: %s" % (iface, rec))
                nid = rec['network_id']

                # Required for initialisation
                if nid not in netid_rec:
                    netid_rec[nid] = []

                # Append interface on that network id
                netid_rec[nid].append(iface)

        res = {}
        self.generate_static_net_conf_common(netid_rec, res)

        mgmt = get_pool_management_device(self.session)
        log.debug("The pool management device is %s" % mgmt)
        if 'static_management' in netconf:
            assert mgmt not in netconf, \
                "'static_management' should only be specified when management " \
                "device(%s) is not being tested for certification. " % (mgmt)
            log.debug("Create static config for management device %s" % mgmt)
            key_name = "%s_0" % (mgmt)
            res[key_name] = StaticIPManager(netconf['static_management'])
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
            raise Exception("Error: more than two devices "
                            + "for network %s: %s" % (network_ref, devices))

        # In the case of a bond, we do not mind which device is used.
        iface = devices.pop()

        key = "%s_%s" % (iface, vlan)
        if key in list(self.static_managers.keys()):
            return self.static_managers[key]
        else:
            return None

    def get_vlans(self, iface):
        """ For a specified ethernet interface, return the list of 
        VLANs that the user has declared to be in operation."""
        netconf = eval(self.config['netconf'])  # NOSONAR
        if iface not in netconf:
            raise Exception("The interface %s has not been defined in the network config file. (%s)" %
                            (iface, netconf))
        return netconf[iface]['vlan_ids']

    def get_netconf(self):
        """Return the network config dictionary, as provided by the user"""
        return eval(self.config['netconf'])  # NOSONAR

    def singlenicmode(self):
        return 'singlenic' in list(self.config.keys()) and self.config['singlenic'] == 'true'

    def get_equivalent_devices(self):
        """Return a list of interfaces presented by devices with the same PCI ID as
        the one currently being tested by the testkit"""

        equiv_ifaces = intersection(get_equivalent_devices(self.session,
                                                           self.config['device_config']),
                                    list(self.get_netconf().keys()))

        log.debug("Equivalent devices for %s: %s" % (self.config['device_config']['Kernel_name'],
                                                     equiv_ifaces))
        return equiv_ifaces

    def get_pifs_to_use(self):
        equiv_devs = self.get_equivalent_devices()
        try:
            return filter_pif_devices(self.session, equiv_devs)
        except Exception as e:
            log.error(
                "Caught Exception - may be OK if running in single NIC mode.")
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
            # Get no management ethernet devices
            devices = filter_pif_devices(self.session, device_list)

        results = []
        for device in devices:
            # Array access exception would be raised by filter_pif_devices
            pifs = get_pifs_by_device(self.session, device)

            # Assumption that two PIFs are on the same network
            network_ref = self.session.xenapi.PIF.get_network(pifs[0])
            if len(pifs) > 1:
                for pif in pifs[1:]:
                    if self.session.xenapi.PIF.get_network(pif) != network_ref:
                        raise Exception("Assumption that identical devices " +
                                        "in a pool are attached to the same " +
                                        "network is invalid!")
            results.append(network_ref)

        # Raise an exception if no networks have been found
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
        host_refs = self.session.xenapi.host.get_all()
        for host_ref in host_refs:
            oc = self.session.xenapi.host.get_other_config(host_ref)
            default_routes_key = 'default_routes'
            if default_routes_key not in list(oc.keys()):
                routes = get_network_routes(self.session, host_ref)
                route_recs = [route.get_record() for route in routes]
                oc[default_routes_key] = str(route_recs)
                self.session.xenapi.host.set_other_config(host_ref, oc)

        backend = call_ack_plugin(self.session, 'get_network_backend')
        log.debug("Current network backend: %s" % backend)
        log.debug("self.network_backend %s" % self.network_backend)
        if self.network_backend == 'vswitch' and backend == 'bridge':
            # Switch backend to vswitch
            call_ack_plugin(self.session, 'set_network_backend_pool',
                            {'backend': 'openvswitch'})
            host_reboot(self.session)
        elif self.network_backend == 'bridge' and backend == 'openvswitch':
            # Switch backend to bridge
            call_ack_plugin(self.session, 'set_network_backend_pool',
                            {'backend': 'bridge'})
            host_reboot(self.session)

    def get_bondable_ifaces(self, iface):
        """ Given a particular interface, return a list of other network
        interfaces which have been defined as being on the same physical L2 network."""
        netconf = self.get_netconf()
        phy_id = netconf[iface]['network_id']

        log.debug("NetConf: '%s'" % netconf)
        # Construct a list of interface names who have the same physical ID
        # as the provided interface.

        blist = intersection([k for k, v in netconf.items() if k.startswith('eth') and
                              v['network_id'] == phy_id],
                             list(netconf.keys()))

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


class PerformanceTest(TestClass):
    # Deine the test timeout in seconds and the number of test VMs
    timeout = 3600
    vm_count = 3

    # SSH command variables
    username = 'root'
    password = DEFAULT_PASSWORD

    # Class variables
    test = ''
    cmd_str = ''

    def _call_plugin(self, session, vm_ref_list, call):
        """Util function to call ACK plugin method"""
        res = []
        for vm_ref in vm_ref_list:
            res.append(call_ack_plugin(self.session, call,
                                       {'vm_ref': vm_ref,
                                        'mip': get_context_vm_mip(vm_ref),
                                        'username': self.username,
                                        'password': self.password}))
        return res

    def _create_test_threads(self, session, vm_ref_list):
        """Spawns a new non-blocking test thread for each VM and
        returns a reference object to these threads.  Each thread is
        a timeout function of function self.cmd_str which is run on
        the master host by the XenAPI plugin"""
        threads = []
        for vm_ref in vm_ref_list:
            threads.append(create_test_thread(lambda vm=vm_ref: TimeoutFunction(ssh_command(get_context_vm_mip(vm),
                                                                                            self.username,
                                                                                            self.password,
                                                                                            self.cmd_str),
                                                                                self.timeout, '%s test timed out %d' % (self.test, self.timeout))))
        return threads

    def _setup_vms(self, session):
        """Interface to create VMs by child class"""
        return []

    def _run_test(self, session):
        """Main run fuction.  Sets up the VMs, deploys the test,
        spawns the test threads, and tracks the threads until they
        all complete"""
        # setup vms
        vm_ref_list = self._setup_vms(session)

        # Make certain the VMs are available
        for vm_ref in vm_ref_list:
            check_vm_ping_response(session, vm_ref, get_context_vm_mip(vm_ref))

        # deploy test rpms
        log.debug("Deploying test RPMs")
        self._call_plugin(session, vm_ref_list, 'deploy_' + self.test)

        # create and start test threads, wait until complete
        log.debug("About to run %s test..." % self.test)
        threads = self._create_test_threads(session, vm_ref_list)

        # Wait for the threads to finish running or timeout
        start = time.time()
        while check_test_thread_status(threads):
            time.sleep(1)
            if should_timeout(start, self.timeout):
                raise Exception("%s test timed out %s" %
                                (self.test, self.timeout))

        # retrieve the logs
        log.debug("%s test is complete, retrieving logs" % self.test)
        self._call_plugin(session, vm_ref_list,
                          'retrieve_' + self.test + '_logs')

        return {'info': 'Test ran successfully'}


class LocalStorageTestClass(PerformanceTest):
    """Sub class for storage tests"""
    base_tag = 'LS'


class CPUTestClass(PerformanceTest):
    """Sub class for CPU tests"""
    base_tag = 'CPU'


class OperationsTestClass(TestClass):
    """Sub class for Operations tests"""
    base_tag = 'OP'
