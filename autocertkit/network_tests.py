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

"""A module for network specific tests"""

import testbase
from utils import *
import os.path
import sys
import math
import traceback


class FixedOffloadException(Exception):
    pass


class IperfTest:
    """Utility class for running an Iperf test between two VMs
    or Dom0 + VM. This class can be setup and consumed by
    other test classes in this module"""

    default_config = {'window_size': '256K',
                      'format': 'm',
                      'buffer_length': '256K',
                      'thread_count': '1'}

    default_iface_config = {'iface_m': 'eth0',
                            'ip_m': '',
                            'iface_t': '',
                            'ip_t': '',
                            'mac_t': ''}

    def __init__(self, session,
                 client_vm_ref,
                 server_vm_ref,
                 network_ref,
                 static_manager,
                 opt):

        self.session = session
        self.server = server_vm_ref
        self.client = client_vm_ref
        self.network = network_ref
        self.static_manager = static_manager
        self.username = opt.get('username', 'root')
        self.password = opt.get('password', DEFAULT_PASSWORD)
        self.multicast_ip = opt.get('multicast_ip', '')
        self.max_retry_on_failure = opt.get('max_retry_on_failure', 3)

        # Interface and IP etc on server/client to (t)est and (m)anagement
        self.vm_info = opt.get('vm_info', None)

        self.config = opt.get('config', self.default_config)

        # Store pool master in order to make plugin calls
        self.host = get_pool_master(self.session)

        self.timeout = 60

        # Validate the references and setup run method
        # self.validate_refs()

    def init_vm_info(self):
        if self.vm_info:
            return
        self.vm_info = {self.server: self.default_iface_config.copy(),
                        self.client: self.default_iface_config.copy()}
        for vm_ref in [self.server, self.client]:
            if self.session.xenapi.VM.get_is_control_domain(vm_ref):
                self.vm_info[vm_ref]['iface_m'] = ""
                self.vm_info[vm_ref]['ip_m'] = ""
            else:
                mif = get_context_vm_mif(vm_ref)
                self.vm_info[vm_ref]['iface_m'] = mif[0]
                self.vm_info[vm_ref]['ip_m'] = mif[2]
            test_if = get_context_test_ifs(vm_ref)[0]
            self.vm_info[vm_ref]['iface_t'] = test_if[0]
            self.vm_info[vm_ref]['mac_t'] = test_if[1]
            self.vm_info[vm_ref]['ip_t'] = test_if[2]

    def validate_refs(self):
        """Check that the specified references are valid,
        and in a configuration that is supported."""

        if self.session.xenapi.VM.get_is_control_domain(self.server):
            raise Exception("Expecting Dom0 to be the client, not the server")

    def record_stats(self):
        """Record the interface statistics before running any tests"""
        self.stats_rec = {self.client: self.get_iface_stats(self.client),
                          self.server: self.get_iface_stats(self.server)}

    def validate_stats(self, bytes_sent):
        # Load previous
        client_stats = self.stats_rec[self.client]
        server_stats = self.stats_rec[self.server]

        # Obtain current
        log.debug("Get Client Stats:")
        client_now_stats = self.get_iface_stats(self.client)
        log.debug("Get Server Stats:")
        server_now_stats = self.get_iface_stats(self.server)

        itsv_cli = IperfTestStatsValidator(client_stats, client_now_stats)
        itsv_srv = IperfTestStatsValidator(server_stats, server_now_stats)

        log.debug("Validate Client tx_bytes")
        itsv_cli.validate_bytes(bytes_sent, 'tx_bytes')
        log.debug("Validate Server rx_bytes")
        itsv_srv.validate_bytes(bytes_sent, 'rx_bytes')

    def configure_routes(self):
        """Ensure that the routing table is setup correctly in the client"""
        log.debug("Configuring routes...")

        # Make a plugin call to add a route to the client
        self.plugin_call('add_route',
                         {'vm_ref': self.client,
                          'mip': self.vm_info[self.client]['ip_m'],
                          'dest_ip': self.vm_info[self.server]['ip_t'],
                          'dest_mac': self.vm_info[self.server]['mac_t'],
                          'device': self.vm_info[self.client]['iface_t'],
                          'src': self.vm_info[self.client]['ip_t']}
                         )

        self.plugin_call('add_route',
                         {'vm_ref': self.server,
                          'mip': self.vm_info[self.server]['ip_m'],
                          'dest_ip': self.vm_info[self.client]['ip_t'],
                          'dest_mac': self.vm_info[self.client]['mac_t'],
                          'device': self.vm_info[self.server]['iface_t'],
                          'src': self.vm_info[self.server]['ip_t']}
                         )

        if self.multicast_ip:
            self.plugin_call('add_route',
                             {'vm_ref': self.client,
                              'mip': self.vm_info[self.client]['ip_m'],
                              'dest_ip': self.multicast_ip,
                              'mask': '240.0.0.0',  # NOSONAR
                              'device': self.vm_info[self.client]['iface_t'],
                              'src': self.vm_info[self.client]['ip_t']}
                             )

            self.plugin_call('add_route',
                             {'vm_ref': self.server,
                              'mip': self.vm_info[self.server]['ip_m'],
                              'dest_ip': self.multicast_ip,
                              'mask': '240.0.0.0',  # NOSONAR
                              'device': self.vm_info[self.server]['iface_t'],
                              'src': self.vm_info[self.server]['ip_t']}
                             )

    def run(self):
        """This classes run test function"""
        self.init_vm_info()

        # Configure routes
        self.configure_routes()

        ping_with_retry(self.session, self.client, self.vm_info[self.client]['ip_m'],
                        self.vm_info[self.server]['ip_t'],
                        self.vm_info[self.client]['iface_t'])

        self.deploy_iperf()

        self.run_iperf_server()
        log.debug("IPerf deployed and server started")

        attempt_count = 0
        fail_data = {}
        while attempt_count < self.max_retry_on_failure:
            attempt_count += 1
            try:
                log.debug("Test attempt count %d" % attempt_count)

                # Capture interface statistics pre test run
                self.record_stats()

                iperf_test_inst = TimeoutFunction(self.run_iperf_client,
                                                  self.timeout,
                                                  'iPerf test timed out %d' % self.timeout)

                # Run the iperf tests
                iperf_data = iperf_test_inst()

                # Wait for seconds to let all packs reach iperf server
                time.sleep(3)

                # Capture interface statistcs post test run
                bytes_transferred = int(iperf_data['transfer'])
                self.validate_stats(bytes_transferred)
            except Exception as e:
                traceb = traceback.format_exc()
                log.warning(traceb)
                fail_data["failed_attempt_%d" % (attempt_count)] = str(e)
                time.sleep(10)
            else:
                break
        else:
            raise Exception("Iperf multiple attempts failed: %s" % fail_data)

        return iperf_data

    def deploy_iperf(self):
        """deploy iPerf on both client and server"""
        def deploy(vm_ref):
            self.plugin_call('deploy_iperf',
                             {'vm_ref': vm_ref,
                              'mip': self.vm_info[vm_ref]['ip_m'],
                              'username': self.username,
                              'password': self.password})

        deploy(self.client)
        deploy(self.server)

    def get_iface_stats(self, vm_ref):
        # Make plugin call to get statistics
        return get_iface_statistics(self.session, vm_ref, self.vm_info[vm_ref]['ip_m'], self.vm_info[vm_ref]['iface_t'])

    def run_iperf_server(self):
        """Start the iPerf server listening on a VM"""
        log.debug("Starting IPerf server")
        if self.session.xenapi.VM.get_is_control_domain(self.server):
            host_ref = self.session.xenapi.VM.get_resident_on(self.server)
            log.debug("Host ref = %s" % host_ref)
            args = {'ip': self.vm_info[self.server]['ip_t']}
            call_ack_plugin(self.session,
                            'start_iperf_server',
                            args,
                            host=host_ref)
        else:
            mip = self.vm_info[self.server]['ip_m']
            if self.multicast_ip:
                test_ip = self.multicast_ip
                protocol = '-u'
            else:
                test_ip = self.vm_info[self.server]['ip_t']
                protocol = ''

            cmd_str = "iperf -s -D %s -B %s < /dev/null >&/dev/null" \
                      % (protocol, test_ip)
            ssh_command(mip, self.username, self.password, cmd_str)

    def parse_iperf_line(self, data):
        """Take a CSV line from iperf, parse, returning a dictionary"""
        lines = data.strip().split('\n')
        log.debug("Iperf Lines: %s" % lines)
        arr = lines[0].split(',')
        rec = {}
        rec['datetime'] = arr[0]
        rec['client_ip'] = arr[1]
        rec['client_port'] = arr[2]
        rec['server_ip'] = arr[3]
        rec['server_port'] = arr[4]
        rec['id'] = arr[5]
        rec['interval'] = arr[6]
        rec['transfer'] = arr[7]
        rec['bandwidth'] = arr[8]
        # The the case where iperf returned information, it will seperate it from the csv format
        # by a new line character. We would like to capture this information, and pass it
        # back to the called. So insert into the record field 'info'.
        if len(lines) > 1:
            # Join any extra lines back together again
            rec['info'] = " ".join(lines[1:])
        return rec

    def plugin_call(self, method, args):
        """Make a plugin call to autocertkit"""
        return call_ack_plugin(self.session, method, args, self.host)

    def get_iperf_client_cmd(self):
        params = []

        def copy(param, arg_str):
            if param in self.config.keys() and self.config[param]:
                params.append(arg_str % self.config[param])

        copy('window_size', '-w %s')
        copy('buffer_length', '-l %s')
        copy('format', '-f %s')
        copy('thread_count', '-P %s')

        if self.multicast_ip:
            test_ip = self.multicast_ip
            protocol = '-u'
        else:
            test_ip = self.vm_info[self.server]['ip_t']
            protocol = ''

        cmd_str = "iperf -y csv %s %s -m -B %s -c %s" % \
                  (protocol, " ".join(params),
                   self.vm_info[self.client]['ip_t'], test_ip)
        return cmd_str

    def run_iperf_client(self):
        """Run test iperf command on droid VM"""
        log.debug("Starting IPerf client")
        if self.session.xenapi.VM.get_is_control_domain(self.client):
            # Run client via XAPI plugin
            log.debug("Executing iperf test from Dom0 (%s (%s) --> %s (%s))" %
                      (self.session.xenapi.VM.get_name_label(self.client),
                       self.client,
                       self.session.xenapi.VM.get_name_label(self.server),
                       self.server))

            args = {}

            def copy(param):
                if param in self.config.keys() and self.config[param]:
                    args[param] = self.config[param]

            copy('window_size')
            copy('format')
            copy('buffer_length')
            copy('thread_count')
            args['dst'] = self.vm_info[self.server]['ip_t']
            args['vm_ref'] = self.client

            result = self.plugin_call('iperf_test', args)
        else:
            # Run the client locally
            cmd_str = self.get_iperf_client_cmd()
            result = ssh_command(self.vm_info[self.client]['ip_m'],
                                 self.username, self.password, cmd_str)["stdout"]
        return self.parse_iperf_line(result)


class VLANTestClass(testbase.NetworkTestClass):
    """A test class for ensuring that hardware
    can cope with VLAN traffic correctly"""

    required_config = ['device_config', 'vlan_id']
    tags = ['DEMO']
    default_vlan = 800
    num_ips_required = 4

    def test_vlan_high_port(self, session):
        """This test creates two VMs, one on each host in the pool
        and attempts to send traffic through a VLAN network which is
        plugged into the second interface on each VM."""
        log.debug("Starting to run testVLANHighPort...")

        devices = self.get_pifs_to_use()

        # Take just the first available device to test
        device = devices[0]

        vlans = self.get_vlans(device)
        vlans.sort()
        vlan_id = vlans.pop()

        log.debug("VLAN ID = %d (Alternatives: %s)" % (vlan_id, vlans))

        vlan_network_ref = create_network(session, 'testvlan', '', {})

        for pif_ref in get_pifs_by_device(session, device):
            log.debug("Creating VLAN for PIF %s" % pif_ref)
            log.debug("Network ref = %s vlan_id = %s" %
                      (vlan_network_ref, vlan_id))
            create_vlan(session, pif_ref,
                        vlan_network_ref, vlan_id)

        log.debug("VLAN for PIF created")

        management_network_ref = get_management_network(session)
        network_refs = [management_network_ref, vlan_network_ref]

        # We may want to allocate static addresses to the different interfaces
        # differently, so collect the static ip managers in a record.
        sms = {}
        sms[management_network_ref] = self.get_static_manager(
            management_network_ref)
        sms[vlan_network_ref] = self.get_static_manager(
            vlan_network_ref, vlan=vlan_id)

        # Deploy two VMs
        vm1_ref, vm2_ref = deploy_two_droid_vms(session, network_refs, sms)

        vm1_ip = get_context_vm_mip(vm1_ref)
        log.debug("IP address for vm1 is %s" % vm1_ip)
        vm2_ip = get_context_vm_mip(vm2_ref)
        log.debug("IP address for vm2 is %s" % vm2_ip)

        vm2_test_dev, _, vm2_test_ip = get_context_test_ifs(vm2_ref)[0]

        # Make certain the VMs are available
        for vm_ref in [vm1_ref, vm2_ref]:
            check_vm_ping_response(session, vm_ref, get_context_vm_mip(vm_ref))
            
        # Run Ping Command
        ping_result = ping(vm1_ip, vm2_test_ip, vm2_test_dev)
        log.debug("Result: %s" % ping_result)

        rec = {}
        rec['info'] = ping_result

        if " 0% packet loss" not in ping_result:
            raise TestCaseError("Error: Ping transmittion failed. %s"
                                % ping_result)

        return rec


class BondingTestClass(testbase.NetworkTestClass):
    """A test class for ensuring that hardware
        can cope with network bonding correctly"""

    required_config = ['device_config']
    num_ips_required = 2

    def _setup_network(self, session, mode):
        """Util function for creating a pool-wide network, 
            NIC bond of specified mode on each host"""
        log.debug("Setting up %s NIC bond" % mode)
        net_ref = create_network(session, 'bond0', '', {})
        log.debug("Created network %s" % net_ref)

        # Use the first physical interface returned
        self.piface = self.get_primary_bond_iface()[0]
        # Use the first bondable interface for the specified physical interface
        # above
        self.siface = self.get_bondable_ifaces(self.piface)[0]

        # Organize the correct PIF ref sets
        pifs_ref_set_by_host = []
        for host in session.xenapi.host.get_all():
            pif1 = get_pifs_by_device(session, self.piface, [host])
            pif2 = get_pifs_by_device(session, self.siface, [host])
            pifs_ref_set_by_host.append(pif1 + pif2)

        # Create nic bond
        for pifs_ref_set in pifs_ref_set_by_host:
            log.debug("Bonding PIF set %s to network %s" %
                      (pifs_ref_set, net_ref))
            create_nic_bond(session, net_ref, pifs_ref_set, '', mode)
        # Ensure that hosts come back online after creating these bonds.
        wait_for_hosts(session)

        management_network_ref = get_management_network(session)
        return [management_network_ref, net_ref]

    def _setup_vms(self, session, net_refs):
        """Util function for returning VMs to run bonding test on"""
        log.debug("Setting up droid vms...")

        # Use the static configuration for each interface as defined by the user
        # for the physical network ID being used.
        sms = {}
        for net_ref in net_refs:
            sms[net_ref] = self.get_static_manager(net_ref)

        return deploy_two_droid_vms(session, net_refs, sms)

    def _run_test(self, session, mode):
        """Test control method for configuring the NIC bond,
            configuring the test VMs, and testing for an active 
            network connection while the NIC bond is degraded.
            Returns failure if any packet loss."""
        net_refs = self._setup_network(session, mode)
        vm1_ref, vm2_ref = self._setup_vms(session, net_refs)

        vm1_ip = get_context_vm_mip(vm1_ref)
        vm2_bondnic_dev, _, vm2_bondnic_ip = get_context_test_ifs(vm2_ref)[0]

        for vm_ref in [vm1_ref, vm2_ref]:
            check_vm_ping_response(session, vm_ref, get_context_vm_mip(vm_ref))

        log.debug("Starting test...")
        results = []
        # First time try ping to make sure network stable
        ping(vm1_ip, vm2_bondnic_ip, vm2_bondnic_dev)

        # Test healthy bond
        results.append(ping(vm1_ip, vm2_bondnic_ip, vm2_bondnic_dev))

        # Test degraded bond
        set_nic_device_status(session, self.piface, 'down')
        results.append(ping(vm1_ip, vm2_bondnic_ip, vm2_bondnic_dev))

        # Test degraded bond
        set_nic_device_status(session, self.piface, 'up')
        set_nic_device_status(session, self.siface, 'down')
        results.append(ping(vm1_ip, vm2_bondnic_ip, vm2_bondnic_dev))

        set_nic_device_status(session, self.siface, 'up')

        rec = {}
        rec['data'] = results
        rec['config'] = mode

        for result in results:
            if not valid_ping_response(result, 20):
                raise TestCaseError("Error: Ping transmittion failed for bond type: %s. %s"
                                    % (mode, result))
            else:
                log.debug("Ping Result: %s" % result)

        return rec

    def test_nic_bond_balance_slb(self, session):
        """NIC bonding test case for balance-slb type bond"""
        log.debug("Starting to run test_nic_bond_balance_slb...")
        return self._run_test(session, 'balance-slb')

    def test_nic_bond_active_backup(self, session):
        """NIC bonding test class for active-backup type bond"""
        log.debug("Starting to run test_nic_bond_active_backup...")
        return self._run_test(session, 'active-backup')


class IperfTestClass(testbase.NetworkTestClass):
    """A base Iperf class for running iperf
    between two VMs. This can be subclassed by other
    performance related tests which set/monitor other
    properities"""

    IPERF_ARGS = {'window_size': '256K',
                  'format': 'm',
                  'buffer_length': '256K',
                  'thread_count': '4'}

    required_config = ['device_config']
    network_for_test = None
    num_ips_required = 2
    mode = "vm-vm"
    MULTICAST_IP = ""

    def __init__(self, session, config):
        super(IperfTestClass, self).__init__(session=session, config=config)

    def _setup_network(self, session):
        """Utility method for returning the network reference to be used by VMs"""
        management_network_ref = get_management_network(session)

        # Pick a network to use for testing that exercises the device
        # are wanting to test
        self.network_for_test = self.get_networks()[0]

        log.debug("Network for testing with: %s" % self.network_for_test)

        return [management_network_ref, self.network_for_test]

    def _setup_vms(self, session, network_refs):
        """Util function for returning VMs to run IPerf test on,
        can be subclassed to run different configurations"""
        # Setup default static manager with the available interfaces
        sms = {}
        for network_ref in network_refs:
            sms[network_ref] = self.get_static_manager(network_ref)

        return deploy_two_droid_vms(session, network_refs, sms)

    def _setup_dom0_to_vm(self, session, network_refs):
        sms = {}
        for network_ref in network_refs:
            sms[network_ref] = self.get_static_manager(network_ref)

        log.debug("Get dom0")
        vm1_ref = get_master_control_domain(session)
        device = get_dom0_device_name(session, vm1_ref, self.network_for_test)
        wait_for_dom0_device_ip(session, vm1_ref, device,
                                sms[self.network_for_test])

        log.debug("Create droid")
        slave_ref = get_pool_slaves(session)[0]
        vm2_ref = deploy_common_droid_vms_on_hosts(
            session, [slave_ref], network_refs, 1, sms)[slave_ref][0]
        log.debug("droid created")

        return vm1_ref, vm2_ref

    def _setup_dom0_to_dom0(self, session):
        static_manager = self.get_static_manager(self.network_for_test)
        log.debug("Get dom0 for master")
        vm1_ref = get_master_control_domain(session)
        device = get_dom0_device_name(session, vm1_ref, self.network_for_test)
        wait_for_dom0_device_ip(session, vm1_ref, device, static_manager)

        log.debug("Get dom0 for slave")
        vm2_ref = get_slave_control_domain(session)
        device = get_dom0_device_name(session, vm2_ref, self.network_for_test)
        wait_for_dom0_device_ip(session, vm2_ref, device, static_manager)
        return vm1_ref, vm2_ref

    def _run_test(self, session, direction):

        log.debug("Testing with mode %s" % direction)

        # Use the first available network to run tests on
        network_refs = self._setup_network(session)

        if self.mode == "vm-vm":
            vm1_ref, vm2_ref = self._setup_vms(session, network_refs)
        elif self.mode == "dom0-dom0":
            vm1_ref, vm2_ref = self._setup_dom0_to_dom0(session)
        elif self.mode == "dom0-vm":
            vm1_ref, vm2_ref = self._setup_dom0_to_vm(session, network_refs)

        # Determine which reference should be the server and
        # which should be the client.
        if direction == 'rx':
            client = vm2_ref
            server = vm1_ref
        elif direction == 'tx':
            client = vm1_ref
            server = vm2_ref
        else:
            raise Exception(
                "Unknown 'direction' key specified. Expected tx or rx")

        log.debug("Client IPerf VM ref: %s" % client)
        log.debug("Server IPerf VM ref: %s" % server)

        log.debug("About to run iperf test...")
        iperf_data = IperfTest(session, client, server, self.network_for_test,
                               self.get_static_manager(self.network_for_test),
                               {'config': self.IPERF_ARGS,
                                   'multicast_ip': self.MULTICAST_IP}
                               ).run()

        return {'info': 'Test ran successfully',
                'data': iperf_data,
                'config': self.IPERF_ARGS}

    def test_tx_throughput(self, session):
        """Generic throughput Iperf test"""
        direction = 'tx'
        return self._run_test(session, direction)

    def test_rx_throughput(self, session):
        """Generic throughput Iperf test"""
        direction = 'rx'
        return self._run_test(session, direction)


class PIFParamTestClass(IperfTestClass):
    """A test calss for ensuring all PIF params
        can be set, modified, and op's verrified"""

    # Offload configs to be used in tests.
    # If an offload is fixed to in wrong states, log and continue tests.
    # If an offload is not fixed and in wrong states, test fails.
    OFFLOAD_CONFIG = {'sg': 'on',
                      'tso': 'on',
                      'gso': 'on',
                      'gro': 'off',
                      'lro': 'off',
                      'rxvlan': 'on',
                      'txvlan': 'on'}
    num_ips_required = 2

    def _set_offload_params(self, session, pif):
        """ Set offload setting."""
        log.debug(self.OFFLOAD_CONFIG)
        device = session.xenapi.PIF.get_device(pif)
        log.debug("Device: %s" % device)
        for k, v in self.OFFLOAD_CONFIG.items():
            set_hw_offload(session, device, k, v)

    def _verify_ethtool_offloads(self, session, device):
        """Check that the device specified has the correct
        hw offload configuration"""

        hw_offloads = get_hw_offloads(session, device)
        log.debug("verify offloads...%s" % hw_offloads)
        for k, v in self.OFFLOAD_CONFIG.items():
            if k not in hw_offloads:
                raise Exception("Cannot determine status of %s." % k)
            log.debug("Device: %s (%s offload: %s)" %
                      (device, k, hw_offloads[k]))
            if not hw_offloads[k].startswith(v):
                # Newest ethtool will tell whether the offload setting can be changed.
                # If it is not possible due to the hardware ristriction, then ACK should
                # ignore this failure and keep running tests.
                if '[fixed]' in hw_offloads[k]:
                    log.debug("Required offload %s is fixed to %s." %
                              (k, hw_offloads[k]))
                else:
                    raise Exception(
                        "%s offload was not in the correct state (is %s)" % (k, hw_offloads[k]))

    def _setup_pif_params(self, session, network_ref):
        pifs = session.xenapi.network.get_PIFs(network_ref)
        log.debug("PIFs retrieved %s" % pifs)
        # Set argument on PIF
        for pif in pifs:
            self._set_offload_params(session, pif)
            device = session.xenapi.PIF.get_device(pif)
            self._verify_ethtool_offloads(session, device)

    def _setup_network(self, session):
        network_refs = IperfTestClass._setup_network(self, session)
        log.debug("Network_refs = %s" % network_refs)

        management_network_ref = get_management_network(session)

        for network_ref in network_refs:

            # Don't configure PIF params for the management NIC
            if network_ref != management_network_ref:
                # Setup Pif Params
                self._setup_pif_params(session, network_ref)

        return network_refs


########## Dom0 to VM Iperf Test Classes ##########

class Dom0VMIperfTestClass(PIFParamTestClass):
    """A subclass of the PIFParamTest class, this
    class runs the tests between Dom0 and a VM,
    rather than just between VMs"""

    mode = "dom0-vm"
    IPERF_ARGS = {'format': 'm',
                  'thread_count': '1'}


class Dom0VMBridgeIperfTestClass(Dom0VMIperfTestClass):
    """Subclass that runs the appropriate tests with bridge as the default backend."""
    network_backend = "bridge"
    order = 5


########## Dom0 to Dom0 PIF parameter test classes #########

class Dom0PIFParamTestClass1(PIFParamTestClass):
    """A class for Dom0 - VM PIF param testing"""

    mode = "dom0-dom0"


class Dom0PIFParamTestClass2(Dom0PIFParamTestClass1):
    """A class for Dom0 - VM PIF param testing"""

    caps = []
    required = False
    OFFLOAD_CONFIG = {'sg': 'on',
                      'tso': 'on',
                      'gso': 'on',
                      'gro': 'off',
                      'lro': 'off',
                      'rxvlan': 'on',
                      'txvlan': 'on'}


class Dom0PIFParamTestClass3(Dom0PIFParamTestClass1):
    """A class for Dom0 - VM PIF param testing"""

    caps = []
    required = False
    OFFLOAD_CONFIG = {'sg': 'on',
                      'tso': 'on',
                      'gso': 'on',
                      'gro': 'on',
                      'lro': 'off',
                      'rxvlan': 'on',
                      'txvlan': 'on'}

########## Dom0 to Dom0 *Bridge* PIF parameter test classes #########


class Dom0BridgePIFParamTestClass1(PIFParamTestClass):
    """A class for Dom0 - VM PIF param testing"""

    network_backend = "bridge"
    mode = "dom0-dom0"
    order = 5


class Dom0BridgePIFParamTestClass2(Dom0BridgePIFParamTestClass1):
    """A class for Dom0 - VM PIF param testing"""

    caps = []
    required = False
    OFFLOAD_CONFIG = {'sg': 'on',
                      'tso': 'on',
                      'gso': 'on',
                      'gro': 'off',
                      'lro': 'off',
                      'rxvlan': 'on',
                      'txvlan': 'on'}


class Dom0BridgePIFParamTestClass3(Dom0BridgePIFParamTestClass1):
    """A class for Dom0 - VM PIF param testing"""

    caps = []
    required = False
    OFFLOAD_CONFIG = {'sg': 'on',
                      'tso': 'on',
                      'gso': 'on',
                      'gro': 'on',
                      'lro': 'off',
                      'rxvlan': 'on',
                      'txvlan': 'on'}

########## Jumbo Frames (Large MTU) Test Classes ###########


class MTUPingTestClass(testbase.NetworkTestClass):
    """A test class for ensuring that hardware can cope with 
    transmitting large MTU.  Note, this test case is only 
    compatible with the open vswitch backend"""

    MTU = '9000'

    PING_ARGS = {'packet_size': 8000,
                 'packet_count': 20}

    username = 'root'
    password = DEFAULT_PASSWORD

    num_ips_required = 2

    def _setup_network(self, session):
        """Utility method for setting the network MTU and 
        returning the network reference to be used by VMs"""
        net_ref = self.get_networks()[0]

        set_network_mtu(session, net_ref, self.MTU)
        log.debug("Network created and MTU %s set" % self.MTU)

        management_network_ref = get_management_network(session)

        return [management_network_ref, net_ref]

    def _setup_vms(self, session, net_refs):
        """Util function for returning VMs to run large MTU ping test on"""
        sms = {}
        for net_ref in net_refs:
            sms[net_ref] = self.get_static_manager(net_ref)

        return deploy_two_droid_vms(session, net_refs, sms)

    def _run_test(self, session):
        """Runs a ping test using a set MTU and the -M switch,
        for MTU discovery, to verify successful packet delivery to VM2"""

        # setup required network
        net_refs = self._setup_network(session)

        # setup VMs for test
        vm1_ref, vm2_ref = self._setup_vms(session, net_refs)

        # retrieve VM IPs
        vm1_dev, _, vm1_ip = get_context_vm_mif(vm1_ref)
        log_str = "VM %s has IP %s (iface: %s)"
        log.debug(log_str % (vm1_ref, vm1_ip, vm1_dev))

        vm2_dev, _, vm2_ip = get_context_vm_mif(vm2_ref)
        log.debug(log_str % (vm2_ref, vm2_ip, vm2_dev))

        vm1_test_dev, vm1_test_mac, vm1_test_ip \
            = get_context_test_ifs(vm1_ref)[0]
        log.debug(log_str % (vm1_ref, vm1_test_ip, vm1_test_dev))

        vm2_test_dev, vm2_test_mac, vm2_test_ip \
            = get_context_test_ifs(vm2_ref)[0]
        log.debug(log_str % (vm2_ref, vm2_test_ip, vm2_test_dev))

        # Add explicit IP routes to ensure MTU traffic travels
        # across the correct interface.

        args = {
            'vm_ref': vm1_ref,
            'mip': vm1_ip,
            'dest_ip': vm2_test_ip,
            'dest_mac': vm2_test_mac,
            'device': vm1_test_dev,
        }

        call_ack_plugin(session, 'add_route', args)

        args = {
            'vm_ref': vm2_ref,
            'mip': vm2_ip,
            'dest_ip': vm1_test_ip,
            'dest_mac': vm1_test_mac,
            'device': vm2_test_dev,
        }

        call_ack_plugin(session, 'add_route', args)

        for vm_ref in [vm1_ref, vm2_ref]:
            check_vm_ping_response(session, vm_ref, get_context_vm_mip(vm_ref))

        ssh_command(vm1_ip, self.username, self.password,
                    'ip link set dev %s mtu %s' % (vm1_test_dev, self.MTU))
        ssh_command(vm2_ip, self.username, self.password,
                    'ip link set dev %s mtu %s' % (vm2_test_dev, self.MTU))

        log.debug("Starting large MTU ping test...")

        log.debug("Attempt normal ping first...")
        ping_result = ping(vm1_ip, vm2_test_ip, vm1_test_dev)
        log.debug("Normal result: %s" % ping_result)

        log.debug("Moving onto large MTU ping...")
        log.debug("Ping Arguments: %s" % self.PING_ARGS)
        # set ping args and run cmd
        ping_result = ping(vm1_ip, vm2_test_ip, vm1_test_dev, self.PING_ARGS[
                           'packet_size'], self.PING_ARGS['packet_count'])
        log.debug("Result: %s" % ping_result)

        rec = {}
        rec['data'] = ping_result
        rec['config'] = self.PING_ARGS

        # Check for failure
        if " 0% packet loss" not in ping_result:
            raise TestCaseError("Error: Large MTU ping transmission failed. %s"
                                % ping_result)

        return rec

    def test_ping(self, session):
        log.debug("run test...")
        return self._run_test(session)


class MulticastTestClass(IperfTestClass):
    """ Subclass that runs multicast test"""

    REQUIRED_FOR = ">= %s" % XCP_MIN_VER_WITH_MULTICAST
    caps = [MULTICAST_CAP]
    required = False

    IPERF_ARGS = {'format': 'm',
                  'thread_count': '4'}

    MULTICAST_IP = '226.94.1.1'  # NOSONAR


class GROOffloadTestClass(testbase.NetworkTestClass):
    """ Check whether GRO can be on. GRO is on by default from XS 6.5 """
    REQUIRED_FOR = ">= 1.9.0"

    def test_offload_config(self, session):
        net_ref = self.get_networks()[0]
        pifs = session.xenapi.network.get_PIFs(net_ref)
        log.debug("PIFs to test: %s" % pifs)
        # Set argument on PIF
        for pif in pifs:
            device = session.xenapi.PIF.get_device(pif)
            set_hw_offload(session, device, 'gro', 'on')
            gro_offload = get_hw_offloads(session, device)['gro']
            if not gro_offload.startswith('on'):
                raise Exception("GRO offload of %s is not set to on" % device)

        return {'data': "GRO is set to on properly."}


class GROOffloadBridgeTestClass(GROOffloadTestClass):
    """ Check whether GRO can be on with bridge network backend.
    GRO is on by default from XS 6.5 """
    network_backend = "bridge"
    order = 5


class InterHostSRIOVTestClass(IperfTestClass):
    """Iperf test between VF (in VM1 on master) and VIF (in VM2 on slave)"""

    REQUIRED_FOR = ">= %s" % XCP_MIN_VER_WITH_SRIOV
    caps = [SRIOV_CAP]
    required = False

    IPERF_ARGS = {'format': 'm',
                  'thread_count': '4'}

    def _run_test(self, session, direction):
        ret = {}

        '''
        control definition:
          - for modprobe type test because reboot required:
                None:       initial
                'enabled':  sriov enabled and reboot
                'disabled': sriov disabled and reboot
          - for sysfs type test, control is always None
        '''
        test_method = self.config['test_method']
        self.control = test_method.get_control()
        log.debug("SR-IOV test control info: %s" % self.control)

        # check if SR-IOV capability is supported
        if not self.control:
            self._check_sriov_cap(session)

        if not self.control or self.control == "enabled":
            # setup general networks on slave
            management_net_ref, comm_net_ref = self._setup_network(session)
            log.debug("management_net_ref: %s, comm_net_ref: %s" %
                      (management_net_ref, comm_net_ref))

            # setup sriov network on master
            # enable VF, wherein host may require reboot
            reboot, test_net_ref, net_sriov_ref = self._enable_vf(
                session, self.control == "enabled")
            log.debug("reboot: %s, test_net_ref: %s, net_sriov_ref: %s" %
                      (reboot, test_net_ref, net_sriov_ref))
            if reboot:
                self.set_control(ret, "enabled")
                self.set_superior(ret, 'reboot')
                return ret

            # setup VMs for test, make sure VM stopped when assign VF
            vm_list = self._setup_vms(session,
                                      [[management_net_ref, comm_net_ref],
                                       [management_net_ref, test_net_ref]])

            # perform extra operation test
            self.ops_test(session, vm_list)

            # choose 2 VM and perform IPerf test
            self.iperf_test(session, ret, vm_list[0], vm_list[1], direction)

            self._disable_vf(session, vm_list)

            if self.control == "enabled":
                # need to reboot at first
                self.set_control(ret, "disabled")
                self.set_superior(ret, 'reboot')
                return ret

        # verify if sriov is disabled
        if not self.control or self.control == "disabled":
            log.debug("Disable VF done!")
            if session.xenapi.network_sriov.get_all() or not is_vf_disabled(session):
                raise TestCaseError(
                    'Error: SR-IOV test failed. Can not disable.')
            self.set_info(ret, 'Test ran successfully')

        return ret

    def _disable_vf(self, session, vm_list):
        for i in vm_list:
            destroy_vm(session, i)
        log.debug("Disable VF begin")
        # network_sriov may be synced to slave host, so here destroy all, rather than just sriov_net_ref
        for i in session.xenapi.network_sriov.get_all():
            log.debug("Destory network_sriov: %s" % i)
            session.xenapi.network_sriov.destroy(i)

    def _check_sriov_cap(self, session):
        device = self.config['device_config']['Kernel_name']
        has_sriov = has_sriov_cap(session, device)
        if has_sriov:
            log.debug("Device %s has SR-IOV capability" % device)
        else:
            log.debug("Device %s has no SR-IOV capability" % device)
            raise TestCaseError(
                'Error: SR-IOV test failed. SR-IOV capability is not available')

    def _enable_vf(self, session, tried=False):
        master = get_pool_master(session)
        device = self.config['device_config']['Kernel_name']
        network_label = 'test_sriov'

        if not tried:
            # have not enabled, try to
            log.debug("Enable VF begin")
            net_ref, net_sriov_ref = enable_vf(
                session, device, master, network_label)
            reboot = session.xenapi.network_sriov.get_requires_reboot(
                net_sriov_ref)
            if reboot:
                log.debug("Need to reboot host")
                return (True, net_ref, net_sriov_ref)

        log.debug("Enable VF done!")

        # enabled, continue to verify
        pifs = get_pifs_by_device(session, device, [master])
        sriov_nets = session.xenapi.PIF.get_sriov_physical_PIF_of(pifs[0])
        net_sriov_ref = sriov_nets[0]
        vf_num = session.xenapi.network_sriov.get_remaining_capacity(
            net_sriov_ref)
        self.vf_num = int(vf_num)
        log.debug("The number of available VF: %d" % self.vf_num)
        if self.vf_num <= 0:
            raise TestCaseError(
                'Error: SR-IOV test failed. No VF available after enabling')

        net_ref = get_test_sriov_network(session, network_label)

        return (False, net_ref, net_sriov_ref)

    def _setup_vms(self, session, network_refs):
        # Setup default static manager with the available interfaces
        sms = {}
        networks_slave, networks_master = network_refs[0], network_refs[1]
        for i, network_ref in enumerate(networks_slave):
            sms[network_ref] = self.get_static_manager(network_ref)
            sms[networks_master[i]] = sms[network_ref]

        netconf = self.get_netconf()
        device = self.config['device_config']['Kernel_name']
        vf_driver_name = get_value(netconf[device], "vf_driver_name")
        vf_driver_pkg = get_value(netconf[device], "vf_driver_pkg")

        return self.deploy_droid_vms(session, (vf_driver_name, vf_driver_pkg), network_refs, sms)

    def deploy_droid_vms(self, session, vf_driver, network_refs, sms):
        """Virtual function to create specific VMs"""
        return deploy_two_droid_vms_for_sriov_inter_host_test(session, vf_driver, network_refs, sms)

    def iperf_test(self, session, result, vm1_ref, vm2_ref, direction):
        """Virtual function to perform IPerf test"""
        mip = get_context_vm_mip(vm1_ref)
        test_if = get_context_test_ifs(vm1_ref)[0]
        vf_driver_info = get_vf_driver_info(session, get_pool_master(session),
                                            vm1_ref, mip, test_if[0])
        log.debug("vf driver info: %s" % str(vf_driver_info))
        self.set_config(result, vf_driver_info)

        # Determine which reference should be the server and
        # which should be the client.
        if direction == 'rx':
            server, client = vm1_ref, vm2_ref
        elif direction == 'tx':
            server, client = vm2_ref, vm1_ref
        else:
            raise Exception(
                "Unknown 'direction' key specified. Expected tx or rx")
        log.debug("IPerf server VM ref: %s" % server)
        log.debug("IPerf client VM ref: %s" % client)

        log.debug("About to run SR-IOV IPerf test...")
        iperf_data = IperfTest(session, client, server, None, None,
                               {'config': self.IPERF_ARGS}).run()

        self.set_data(result, iperf_data)

    def ops_test(self, session, vms):
        """It's an interface with default, can be overwritten in child class"""
        pass


class IntraHostSRIOVTestClass1(InterHostSRIOVTestClass):
    """Iperf test between VF (in VM1 on master) and VF (in VM2 on master)"""

    def deploy_droid_vms(self, session, vf_driver, network_refs, sms):
        vm_list, _, _ = deploy_droid_vms_for_sriov_intra_host_test_vf_to_vf(
            session, vf_driver, network_refs, sms, vm_count=2, vf_count=2)
        return vm_list


class IntraHostSRIOVTestClass2(InterHostSRIOVTestClass):
    """Assign maximum number of VFs to VMs, 6 per VM at most;
    Do 10 iterations of parallel VM reboots with VF verifying;
    Iperf test between VF (in VM1 on master) and VF (in VM2 on master)"""

    # Max number of NIC per VM is limited to 7 on iCenter, and one of is default eth0 (vif) for management
    MAX_VF_PER_VM = 6

    def deploy_droid_vms(self, session, vf_driver, network_refs, sms):
        device = self.config['device_config']['Kernel_name']
        max_vf_num = get_value(self.get_netconf()[device], "max_vf_num")
        max_vf_num = int(max_vf_num) if max_vf_num else self.vf_num
        self.vf_num_test = min(max_vf_num, self.vf_num)

        vm_num = int(math.ceil(float(self.vf_num_test) / self.MAX_VF_PER_VM))
        if vm_num < 2:
            vm_num = 2
        log.debug("Total VF number: %d, will test %d, needs %d VMs to assign" %
                  (self.vf_num, self.vf_num_test, vm_num))

        vm_list, self.vif_list, self.vif_group = deploy_droid_vms_for_sriov_intra_host_test_vf_to_vf(
            session, vf_driver, network_refs, sms, vm_count=vm_num, vf_count=self.vf_num_test)
        return vm_list

    def ops_test(self, session, vms):
        master_ref = get_pool_master(session)
        test_times = 10
        test_timeout = 3600
        start_time = time.time()

        for i in range(test_times):
            log.debug("Starting test run %d of %d" % (i, test_times))

            log.debug("Shutting down VMs: %s" % vms)
            shutdown_droid_vms(session, vms)
            verify_vif_status(session, self.vif_list, False)

            log.debug("Booting VMs: %s" % vms)
            start_droid_vms(session, [(master_ref, vm) for vm in vms])
            verify_vif_status(session, self.vif_list, True)
            verify_vif_config(session, master_ref, self.vif_group)

            if should_timeout(start_time, test_timeout):
                log.debug("End test because of %d seconds timeout limit" %
                          test_timeout)
                break
