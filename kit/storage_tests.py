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

"""A module for storage specific test cases"""

import testbase
from utils import *

log = get_logger('auto-cert-kit')

class PerfTestClass(testbase.LocalStorageTestClass):
    """A somewhat generic test class for local storage 
    performance tests that could be expanded to include 
    additional plugin-based tasks"""
    
    #Deine the test timeout in seconds and the number of test VMs
    timeout = 3600
    vm_count = 3
    
    #SSH command variables
    username = 'root'
    password = DEFAULT_PASSWORD
    
    #Class variables
    test = ''
    cmd_str = ''
    
    def _setup_vms(self, session):
        """Creates vm_count VMs on the 
        master host's local SR"""
        host_ref = get_pool_master(session)
        net_ref = get_management_network(session)
        sr_ref = get_local_sr(session, host_ref)
        return deploy_count_droid_vms_on_host(session, 
                                              host_ref, 
                                              [net_ref], 
                                              self.vm_count,
                                              {net_ref: self.get_static_manager()},
                                              sr_ref)
        
    def _call_plugin(self, session, vm_ref_list, call):
        """Util function to call a XenAPI plugin"""
        res = []
        host = get_pool_master(session)
        for vm_ref in vm_ref_list:
            res.append(self.session.xenapi.host.call_plugin(host,
                                                            'autocertkit',
                                                            call,
                                                            {'vm_ref': vm_ref,
                                                             'username': self.username,
                                                             'password': self.password}))
        return res
            
    def _create_test_threads(self, session, vm_ref_list):    
        """Spawns a new test thread using the cmd_strin a 
        timeout function over SSH to every VM in vm_ref_list"""
        threads = []
        for vm_ref in vm_ref_list:    
            vm_ip = wait_for_ip(session, vm_ref, 'eth0')
            threads.append(create_test_thread(lambda: TimeoutFunction(ssh_command(vm_ip,
                                                                                  self.username,
                                                                                  self.password,
                                                                                  self.cmd_str),
                                                                      self.timeout, '%s test timed out %d' % (self.test, self.timeout))))
        return threads
        
    def _run_test(self, session):
        """Run test function"""
        #setup vms
        vm_ref_list = self._setup_vms(session)
        
        #Make certain the VMs are available
        for vm_ref in vm_ref_list:
            check_vm_ping_response(session, vm_ref)
                
        #deploy test rpms
        self._call_plugin(session, vm_ref_list, 'deploy_' + self.test)
        
        #create, start test threads, wait until complete
        log.debug("About to run %s test..." % self.test)
        threads = self._create_test_threads(session, vm_ref_list)
        
        #Wait for the threads to finish running or timeout
        start = time.time()
        while check_test_thread_status(threads): 
            time.sleep(1)
            if should_timeout(start, self.timeout):
                raise Exception("%s test timed out %s" % (self.test, self.timeout))
        
        #retrieve the logs
        log.debug("%s test is complete, retrieving logs" % self.test)
        res = self._call_plugin(session, vm_ref_list, 'retrieve_' + self.test + '_logs')

        return {'info': 'Test ran successfully'}
    
    
    def test_iozone(self, session):
        """Perform the IOZone Local Storage benchmark"""
        self.test = 'iozone'
        self.cmd_str = '/usr/bin/iozone -r 4k -r 128k -r 1m -s 128m >> /root/localhost.log'
        return self._run_test(session)

    def test_bonnie(self, session):
        """Perform the Bonnie++ local storage benchmark"""
        config = {'scratch_dir': '/root/bonnie',
                  'file_size': '2000',
                  'count': '1',
                  'user': 'citrix',
                  'log': '2>&1 | tee /root/localhost.log'}
        
        self.test = 'bonnie'
        self.cmd_str = 'bonnie++ -d %s -s %s -x %s -u %s %s' % (config['scratch_dir'],
                                                                config['file_size'],
                                                                config['count'],
                                                                config['user'],
                                                                config['log'])
        return self._run_test(session)
