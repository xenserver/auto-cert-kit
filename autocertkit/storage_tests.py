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

"""A module for storage specific test cases"""

import testbase
from utils import *


class PerfTestClass(testbase.LocalStorageTestClass):
    """A somewhat generic test class for local storage 
    performance tests that could be expanded to include 
    additional plugin-based tasks"""

    def _setup_vms(self, session):
        """Creates vm_count VMs on the 
        master host's local SR"""
        host_ref = get_pool_master(session)
        net_ref = get_management_network(session)
        if 'device_config' in self.config and 'sr' in self.config['device_config']:
            sr_ref = self.config['device_config']['sr']
        else:
            log.debug("Local SR info is not available from device tag.")
            log.debug("Choosing first local SR.")
            sr_ref = get_local_sr(session, host_ref)
        log.debug("%s is chosen for local storage test." % sr_ref)
        return deploy_common_droid_vms_on_hosts(session,
                                                [host_ref],
                                                [net_ref],
                                                self.vm_count,
                                                {net_ref: self.get_static_manager(
                                                    net_ref)},
                                                sr_ref)[host_ref]

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
                                                                config[
                                                                    'file_size'],
                                                                config[
                                                                    'count'],
                                                                config['user'],
                                                                config['log'])
        return self._run_test(session)
