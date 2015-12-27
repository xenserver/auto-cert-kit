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

"""A module for network specific tests"""

import testbase
from utils import *
import os.path
import sys
import math

log = get_logger('auto-cert-kit')

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

    def __init__(self, session, 
                       client_vm_ref, 
                       server_vm_ref, 
                       network_ref,
                       static_manager,
                       username='root', 
                       password=DEFAULT_PASSWORD, 
                       config=None):

        self.session = session
        self.server = server_vm_ref
        self.client = client_vm_ref
        self.network = network_ref
        self.static_manager = static_manager
        self.username = username
        self.password = password

        if not config:
            self.config = self.default_config
        else:
            self.config = config

        # Store pool master in order to make plugin calls
        self.host = get_pool_master(self.session)

        self.timeout = 60

        # Validate the references and setup run method
        #self.validate_refs()

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

        # Make a plugin call to ensure the server is going to recieve
        # packets over the correct interface

        self.plugin_call('reset_arp',
                    {'vm_ref': self.client,
                    })

        self.plugin_call('reset_arp',
                    {'vm_ref': self.server,
                    })
        
        # Make a plugin call to add a route to the client
        self.plugin_call('add_route',
                   {'vm_ref': self.client,
                    'dest_ip': self.get_server_ip(self.get_device_name(self.server)),
                    'dest_mac': get_vm_device_mac(self.session,
                                                  self.server,
                                                  self.get_device_name(self.server),
                                                  ),
                    'device': self.get_device_name(self.client)}
                    )

        self.plugin_call('add_route',
                    {'vm_ref': self.server,
                    'dest_ip': self.get_client_ip(self.get_device_name(self.client)),
                    'dest_mac': get_vm_device_mac(self.session,
                                                  self.client,
                                                  self.get_device_name(self.client),
                                                  ),
                    'device': self.get_device_name(self.server)}
                    )

    def run(self):
        """This classes run test function"""
        self.deploy_iperf()
        self.configure_server_ip()
        self.configure_client_ip()

        self.run_iperf_server()
        log.debug("IPerf deployed and server started")

        # Configure routes
        self.configure_routes()

        # Capture interface statistics pre test run
        self.record_stats()

        iperf_test_inst = TimeoutFunction(self.run_iperf_client, 
                                          self.timeout,
                                          'iPerf test timed out %d' % self.timeout)

        # Run the iperf tests
        iperf_data = iperf_test_inst()
    
        # Capture interface statistcs post test run
        bytes_transferred = int(iperf_data['transfer'])
        self.validate_stats(bytes_transferred)

        return iperf_data

    ############# Utility Functions used by Class ###############
    def get_server_ip(self, iface=None):
        # By default return the interface the server will be listening on

        if not iface:
            iface = self.get_device_name(self.server)

        if self.session.xenapi.VM.get_is_control_domain(self.server):
            # Handle Dom0 Case
            host_ref = self.session.xenapi.VM.get_resident_on(self.server)
            ip = self.session.xenapi.host.call_plugin(host_ref,
                                                      'autocertkit',
                                                      'get_local_device_ip',
                                                      {'device':iface})
            return ip

        else:
            # Handle DroidVM Case
            return wait_for_ip(self.session, self.server, iface)

    def get_client_ip(self, iface='eth0'):
        ip = wait_for_ip(self.session, self.client, iface)
        log.debug("Client (%s) IP for '%s' is '%s'" % (self.client,
                                                       iface,
                                                       ip))
        return ip

    def deploy_iperf(self):
        """deploy iPerf on both client and server"""
        def deploy(vm_ref):
            self.plugin_call('deploy_iperf',
                             {'vm_ref': vm_ref,
                              'username': self.username,
                              'password': self.password})
                             
        deploy(self.client)
        deploy(self.server)

    def get_device_name(self, vm_ref): 
        vm_host = self.session.xenapi.VM.get_resident_on(vm_ref)

        if self.session.xenapi.VM.get_is_control_domain(vm_ref):
            # Handle the Dom0 case
            pifs = self.session.xenapi.network.get_PIFs(self.network)
            device_names = []
            for pif in pifs:
                host_ref = self.session.xenapi.PIF.get_host(pif)
                if vm_host == host_ref:
                    device_names.append(self.session.xenapi.PIF.get_device(pif))
                  
            if len(device_names) > 1:
                raise Exception("Error: expected only a single device " + \
                                "name to be found in PIF list ('%s') " + \
                                "Instead, '%s' were returned." % 
                                                (pifs, device_names))
            device_name = device_names.pop()
            # For control domains, only deal with bridges
            device_name = device_name.replace('eth','xenbr')

        else:
            # Handle the case where we are dealing with a VM
            vm_vifs = self.session.xenapi.VM.get_VIFs(vm_ref)

            filtered_vifs = [vif for vif in vm_vifs \
                      if self.session.xenapi.VIF.get_device(vif) != '0']

            network_vifs = self.session.xenapi.network.get_VIFs(self.network)
    
            int_vifs = intersection(filtered_vifs, network_vifs) 

            if len(int_vifs) > 1:
                raise Exception("Error: more than one VIF connected " + \
                                "to VM '%s' ('%s')" % (int_vifs, filtered_vifs))

            device_name = "eth%s" % \
                          self.session.xenapi.VIF.get_device(int_vifs.pop())

        log.debug("Device under test for VM %s is '%s'" % (vm_ref, device_name))
        return device_name 
    
    def get_iface_stats(self, vm_ref):
        device_name = self.get_device_name(vm_ref)

        # Make plugin call to get statistics
        return get_iface_statistics(self.session, vm_ref, device_name)

    def configure_server_ip(self):
        log.debug("configure_server_ip")
        return self.configure_vm_ip(self.server)

    def configure_client_ip(self):
        log.debug("configure_client_ip")
        return self.configure_vm_ip(self.client)

    def configure_vm_ip(self, vm_ref):
        """Make sure that the client has an IP, which may not be the case
        if we are dealing with Dom0 to Dom0 tests."""
        if self.session.xenapi.VM.get_is_control_domain(vm_ref):
            log.debug("Client VM is Dom0... setup IP on bridge")
            args = {'device': self.get_device_name(vm_ref)}

            if self.static_manager:
                args['mode'] = 'static'
                ip = self.static_manager.get_ip()
                args['ip_addr'] = ip.addr
                args['ip_netmask'] = ip.netmask
            else:
                args['mode'] = 'dhcp'
            
            host_ref = self.session.xenapi.VM.get_resident_on(vm_ref)
            call_ack_plugin(self.session,
                            'configure_local_device',
                            args,
                            host=host_ref)
        else:
            log.debug("Client VM is a droid VM, no need to configure an IP")


    def run_iperf_server(self):
        """Start the iPerf server listening on a VM"""
        log.debug("Starting IPerf server")
        if self.session.xenapi.VM.get_is_control_domain(self.server):
            host_ref = self.session.xenapi.VM.get_resident_on(self.server)
            log.debug("Host ref = %s" % host_ref)

            args = {'device': self.get_device_name(self.server)}

            if self.static_manager:
                args['mode'] = 'static'
                ip = self.static_manager.get_ip()
                args['ip_addr'] = ip.addr
                args['ip_netmask'] = ip.netmask
            else:
                args['mode'] = 'dhcp'

            call_ack_plugin(self.session,
                           'start_iperf_server', 
                            args,
                            host=host_ref)
        else:
            m_ip_address = self.get_server_ip('eth0')
            test_ip = self.get_server_ip()
            cmd_str = "iperf -s -D -B %s < /dev/null >&/dev/null" % test_ip
            ssh_command(m_ip_address, self.username, self.password, cmd_str)    

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
        log.debug("Host: %s Plugin: %s Method: %s Args: %s" %
                  (self.host, 'autocertkit', method, str(args)))
        return self.session.xenapi.host.call_plugin(self.host,
                                                    'autocertkit',
                                                    method,
                                                    args)

    def get_iperf_command(self):
        params = []

        def copy(param, arg_str):
            if param in self.config.keys() and self.config[param]:
                params.append(arg_str % self.config[param])
        
        copy('window_size', '-w %s')
        copy('buffer_length', '-l %s')
        copy('format', '-f %s')
        copy('thread_count', '-P %s')
        
        cmd_str = "iperf -y csv %s -m -c %s" % (" ".join(params), self.get_server_ip())
        return cmd_str

    def run_iperf_client(self):
        """Run test iperf command on droid VM"""
        log.debug("Starting IPerf client")
        if self.session.xenapi.VM.get_is_control_domain(self.client):
            #Run client via XAPI plugin
            log.debug("Executing iperf test from Dom0 (%s (%s) --> %s (%s))" % \
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
            args['dst'] = self.get_server_ip()
            args['vm_ref'] = self.client        

            result = self.plugin_call('iperf_test', args)
        else:
            #Run the client locally
            cmd_str = self.get_iperf_command()
            result = ssh_command(self.get_client_ip(), self.username, self.password, cmd_str)
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

        #Take just the first available device to test
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
        sms[management_network_ref] = self.get_static_manager(management_network_ref)
        sms[vlan_network_ref] = self.get_static_manager(vlan_network_ref, vlan=vlan_id)
        
        #Deploy two VMs
        vm1_ref, vm2_ref = deploy_two_droid_vms(session, network_refs, sms)

        vm1_ip = wait_for_ip(session, vm1_ref, 'eth0')
        log.debug("IP address for vm1 is %s" % vm1_ip)
        vm2_ip = wait_for_ip(session, vm2_ref, 'eth0')
        log.debug("IP address for vm2 is %s" % vm2_ip)

        if 'dhcp' in self.config:
            if self.config['dhcp'].lower() == 'true':
                log.debug("Using DHCP for VMs secondary interface")
                dhcp = True
            else:
                dhcp = False
        else:
            dhcp = False

        log.debug("About to configure network interfaces over SSH")
       
        vm2_eth1_ip = wait_for_ip(session, vm2_ref, 'eth1')

        #Make certain the VMs are available
        for vm_ref in [vm1_ref, vm2_ref]:
            check_vm_ping_response(session, vm_ref)
                
        #Run Ping Command
        ping_result = ping(vm1_ip, vm2_eth1_ip, 'eth1')
        log.debug("Result: %s" % ping_result)

        rec = {}
        rec['info'] = ping_result

        if "0% packet loss" not in ping_result:
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
        # Use the first bondable interface for the specified physical interface above 
        self.siface = self.get_bondable_ifaces(self.piface)[0]
        
        # Organize the correct PIF ref sets
        pifs_ref_set_by_host = []
        for host in session.xenapi.host.get_all():
            pif1 = get_pifs_by_device(session, self.piface, [host])
            pif2 = get_pifs_by_device(session, self.siface, [host])
            pifs_ref_set_by_host.append(pif1 + pif2)
            
        # Create nic bond
        for pifs_ref_set in pifs_ref_set_by_host:
            log.debug("Bonding PIF set %s to network %s" % (pifs_ref_set, net_ref))
            create_nic_bond(session, net_ref, pifs_ref_set, '', mode)
        #Ensure that hosts come back online after creating these bonds.
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
        vm1_ip = wait_for_ip(session, vm1_ref, 'eth0')
        vm2_bondnic_ip = wait_for_ip(session, vm2_ref, 'eth1')

        for vm_ref in [vm1_ref, vm2_ref]:
            check_vm_ping_response(session,vm_ref)
    
        log.debug("Starting test...")
        results = []
        #Test healthy bond
        results.append(ping(vm1_ip, vm2_bondnic_ip, 'eth1'))
        
        #Test degraded bond
        set_nic_device_status(session, self.piface, 'down')
        results.append(ping(vm1_ip, vm2_bondnic_ip, 'eth1'))
        
        #Test degraded bond
        set_nic_device_status(session, self.piface, 'up')
        set_nic_device_status(session, self.siface, 'down')
        results.append(ping(vm1_ip, vm2_bondnic_ip, 'eth1'))
        
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
        log.debug("Setting up VM - VM cross host test")

        # Setup default static manager with the available interfaces    
        sms = {}
        for network_ref in network_refs:
            sms[network_ref] = self.get_static_manager(network_ref)

        return deploy_two_droid_vms(session, network_refs, sms)

    def _setup_dom0_to_vm(self, session, network_refs):
        log.debug("Get dom0")
        vm1_ref = get_master_control_domain(session)

        sms = {}
        for network_ref in network_refs:
            sms[network_ref] = self.get_static_manager(network_ref)
    
        log.debug("Create droid")
        vm2_ref = deploy_slave_droid_vm(session, network_refs, sms)
        log.debug("droid created")
        return vm1_ref, vm2_ref

    def _setup_dom0_to_dom0(self, session):
        log.debug("Get dom0 for master")
        vm1_ref = get_master_control_domain(session)
        log.debug("Get dom0 for slave")
        vm2_ref = get_slave_control_domain(session)
        return vm1_ref, vm2_ref

    def _run_test(self, session, direction):

        log.debug("Testing with mode %s" % direction)
        
        #Use the first available network to run tests on
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
            raise Exception("Unkown 'direction' key specified. Expected tx/rx")

        log.debug("Client IPerf VM ref: %s" % client)
        log.debug("Server IPerf VM ref: %s" % server)
            
        log.debug("About to run iperf test...")

        #Run an iperf test - if failure, an exception should be raised.
        iperf_data = IperfTest(session, client, server, 
                                self.network_for_test,
                                self.get_static_manager(self.network_for_test), 
                                config=self.IPERF_ARGS).run()

        return {'info': 'Test ran successfully',
                'data': iperf_data,
                'config': self.IPERF_ARGS }


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
        for k, v in self.OFFLOAD_CONFIG.iteritems():
            set_hw_offload(session, device, k, v)

    def _verify_ethtool_offloads(self, session, device):
        """Check that the device specified has the correct
        hw offload configuration"""

        hw_offloads = get_hw_offloads(session, device)
        log.debug("verify offloads...%s" % hw_offloads)
        for k, v in self.OFFLOAD_CONFIG.iteritems():
            if k not in hw_offloads:
                raise Exception("Cannot determine status of %s." % k)
            log.debug("Device: %s (%s offload: %s)" % (device, k, hw_offloads[k]))
            if not hw_offloads[k].startswith(v):
                # Newest ethtool will tell whether the offload setting can be changed.
                # If it is not possible due to the hardware ristriction, then ACK should
                # ignore this failure and keep running tests.
                if '[fixed]' in hw_offloads[k]:
                    raise FixedOffloadException("Required offload %s is fixed to %s." % (k, hw_offloads[k]))
                raise Exception("%s offload was not in the correct state (is %s)" % (k, hw_offloads[k]))
                                
    def _setup_pif_params(self, session, network_ref):
        pifs = session.xenapi.network.get_PIFs(network_ref)
        log.debug("PIFs retrieved %s" % pifs)
        #Set argument on PIF
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
                #Setup Pif Params
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
        log.debug("Setting up VM - VM cross host test")

        sms = {}
        for net_ref in net_refs:
            sms[net_ref] = self.get_static_manager(net_ref)

        return deploy_two_droid_vms(session, net_refs, sms)
    
    def _run_test(self, session):
        """Runs a ping test using a set MTU and the -M switch,
        for MTU discovery, to verify successful packet delivery to VM2"""
        
        #setup required network
        net_refs = self._setup_network(session)
        
        #setup VMs for test
        vm1_ref, vm2_ref = self._setup_vms(session, net_refs)
        
        #retrieve VM IPs
        vm1_ip = wait_for_ip(session, vm1_ref, 'eth0')
        log.debug("VM %s has IP %s (iface: eth0)" % (vm1_ref, vm1_ip))

        vm2_ip = wait_for_ip(session, vm2_ref, 'eth0')
        log.debug("VM %s has IP %s (iface: eth0)" % (vm2_ref, vm2_ip))

        vm1_ip_eth1 = wait_for_ip(session, vm1_ref, 'eth1')
        log.debug("VM %s has IP %s (iface: eth1)" % (vm1_ref, vm1_ip_eth1))

        vm2_ip_eth1 = wait_for_ip(session, vm2_ref, 'eth1')
        log.debug("VM %s has IP %s (iface: eth1)" % (vm2_ref, vm2_ip_eth1))


        # Add explicit IP routes to ensure MTU traffic travels
        # across the correct interface.

        args = {
                'vm_ref': vm1_ref,
                'dest_ip': vm2_ip_eth1,
                'dest_mac': get_vm_device_mac(session, vm2_ref, 'eth1'),
                'device': 'eth1',
               }   
        
        call_ack_plugin(session, 'add_route', args)

        args = {
                'vm_ref': vm2_ref,
                'dest_ip': vm1_ip_eth1,
                'dest_mac': get_vm_device_mac(session, vm1_ref, 'eth1'),
                'device': 'eth1',
               }   
        
        call_ack_plugin(session, 'add_route', args)



        for vm_ref in [vm1_ref, vm2_ref]:
            check_vm_ping_response(session, vm_ref)

        ips = [vm1_ip, vm2_ip]
        #SSH to vm 'ifconfig ethX mtu XXXX up'
        cmd_str = 'ifconfig eth1 mtu %s up' % self.MTU
        for vm_ip in ips:
            ssh_command(vm_ip, self.username, self.password, cmd_str)
        
        log.debug("Starting large MTU ping test...")

        log.debug("Attempt normal ping first...")
        ping_result = ping(vm1_ip, vm2_ip_eth1, 'eth1')

        log.debug("Moving onto large MTU ping...")
        log.debug("Ping Arguments: %s" % self.PING_ARGS)
        #set ping args and run cmd
        ping_result = ping(vm1_ip, vm2_ip_eth1, 'eth1', self.PING_ARGS['packet_size'], self.PING_ARGS['packet_count'])
        log.debug("Result: %s" % ping_result)
            
            
        rec = {}
        rec['data'] = ping_result
        rec['config'] = self.PING_ARGS
            
        #Check for failure
        if "0% packet loss" not in ping_result:
            raise TestCaseError("Error: Large MTU ping transmission failed. %s" 
                                % ping_result)
    
        return rec
    
        
    def test_ping(self, session):
        log.debug("run test...")
        return self._run_test(session)


class GROOffloadTestClass(testbase.NetworkTestClass):
    """ Check whether GRO can be on. GRO is on by default from XS 6.5 """
    REQUIRED_FOR = ">= 6.4"

    def test_offload_config(self, session):
        net_ref = self.get_networks()[0]
        pifs = session.xenapi.network.get_PIFs(net_ref)
        log.debug("PIFs to test: %s" % pifs)
        #Set argument on PIF
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
    
