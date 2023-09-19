# Copyright (c) 2005-2022 Citrix Systems Inc.
# Copyright (c) 2023 Cloud Software Group, Inc.
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

import testbase
import time
from utils import *


class VMOpsTestClass(testbase.OperationsTestClass):
    """Test class to determine proper operation of the most
    basic VM procedures"""

    # Deine the number of test VMs
    vm_count = 3

    def _setup_vms(self, session):
        """Creates vm_count VMs on the 
        master host's local SR"""
        host_ref = get_pool_master(session)
        net_ref = get_management_network(session)
        return deploy_common_droid_vms_on_hosts(session,
                                                [host_ref],
                                                [net_ref],
                                                self.vm_count,
                                                {net_ref: self.get_static_manager(net_ref)})[host_ref]

    def test_vm_power_control(self, session):
        """Creates a number of VMs and alterates the power
        state a predefined number of times"""
        vm_ref_list = self._setup_vms(session)
        for i in range(3):
            log.debug("Starting test (power control) run %d of %d" %
                      (i + 1, 3))

            # Make certain the VMs are available
            for vm_ref in vm_ref_list:
                check_vm_ping_response(
                    session, vm_ref, get_context_vm_mip(vm_ref))

            # Shut down all VMs
            log.debug("Shutting down VMs: %s" % vm_ref_list)
            """Note that it is required we build the following 'task_list' 
            in this manner, i.e 'x=vm_ref', so that we can get around a 
            particular issue with Python variable bindings within loops"""
            task_list = [(lambda x=vm_ref: session.xenapi.Async.VM.clean_shutdown(x))
                         for vm_ref in vm_ref_list]
            run_xapi_async_tasks(session, task_list)

            # Verify the VMs report a 'Halted' power state
            log.debug("Verrifying VM power control operations for 'Halted'")
            for vm_ref in vm_ref_list:
                if session.xenapi.VM.get_power_state(vm_ref) != 'Halted':
                    raise Exception(
                        "ERROR: Unexpected power state; VM did not shut down")
                log.debug("VM %s is shut down" % vm_ref)
            log.debug("Verrification complete: All VMs have shut down")

            # Boot all VMs
            log.debug("Booting VMs: %s" % vm_ref_list)
            host_ref = get_pool_master(session)
            task_list = [(lambda x=vm_ref: session.xenapi.Async.VM.start_on(x,
                                                                            host_ref,
                                                                            False,
                                                                            False))
                         for vm_ref in vm_ref_list]
            run_xapi_async_tasks(session, task_list)

            # Verify the VMs report a 'Running' power state
            log.debug("Verrifying VM power control operations for 'Running'")
            for vm_ref in vm_ref_list:
                if session.xenapi.VM.get_power_state(vm_ref) != 'Running':
                    raise Exception(
                        "ERROR: Unexpected power state; VM did not boot")
                log.debug("VM %s is running" % vm_ref)
            log.debug("Verrification complete: All VMs have booted")

            log.debug("Test (power control) run %d of %d has completed successfully" %
                      (i + 1, 3))

            wait_for_vms_ips(session, vm_ref_list)

        rec = {}
        rec['info'] = ("VM power state tests completed successfully.")

        return rec

    def test_vm_reboot(self, session):
        """Creates a number of VMs and continuously reboots
        them a predefined number of times"""
        vm_ref_list = self._setup_vms(session)
        for i in range(3):
            log.debug("Starting test (reboot) run %d of %d" % (i + 1, 3))

            # Make certain the VMs are available
            for vm_ref in vm_ref_list:
                check_vm_ping_response(
                    session, vm_ref, get_context_vm_mip(vm_ref))

            # Reboot all VMs
            log.debug("Rebooting VMs: %s" % vm_ref_list)
            task_list = [(lambda x=vm_ref: session.xenapi.Async.VM.clean_reboot(x))
                         for vm_ref in vm_ref_list]
            run_xapi_async_tasks(session, task_list)

            # Verify the VMs report a 'Running' power state
            log.debug(
                "Verrifying VM power control operations (reboot) for 'Running'")
            for vm_ref in vm_ref_list:
                if session.xenapi.VM.get_power_state(vm_ref) != 'Running':
                    raise Exception("ERROR: Unexpected power state")
                log.debug("VM %s is running after rebooting" % vm_ref)
            log.debug("Verrification complete: All VMs have rebooted")

            log.debug("Test (reboot) run %d of %d has completed successfully" %
                      (i + 1, 3))

            wait_for_vms_ips(session, vm_ref_list)

        rec = {}
        rec['info'] = ("VM reboot test completed successfully")

        return rec

    def test_vm_suspend(self, session):
        """Creates a number of VMs and verifies correct
        suspend/resume functionality through three test runs"""
        vm_ref_list = self._setup_vms(session)
        for i in range(3):
            log.debug("Starting test (suspend) run %d of %d" % (i + 1, 3))

            # Make certain the VMs are available
            for vm_ref in vm_ref_list:
                check_vm_ping_response(
                    session, vm_ref, get_context_vm_mip(vm_ref))

            # Suspend all VMs
            log.debug("Suspending VMs: %s" % vm_ref_list)
            task_list = [(lambda x=vm_ref: session.xenapi.Async.VM.suspend(x))
                         for vm_ref in vm_ref_list]
            start = time.time()
            run_xapi_async_tasks(session, task_list, 1200)
            suspend_time = time.time() - start
            log.debug(
                "Suspend operation returned complete in %s seconds" % suspend_time)

            # Verify the VMs report a 'Suspended' power state
            log.debug("Verrifying VM power control operations for 'Suspended'")
            for vm_ref in vm_ref_list:
                if session.xenapi.VM.get_power_state(vm_ref) != 'Suspended':
                    raise Exception("ERROR: VM %s did not suspend" % vm_ref)
                log.debug("VM %s is suspended" % vm_ref)
            log.debug("Verrification complete: All VMs have been suspended")

            # Resume all VMs
            log.debug("Resuming VMs: %s" % vm_ref_list)
            host_ref = get_pool_master(session)
            task_list = [(lambda x=vm_ref: session.xenapi.Async.VM.resume_on(x,
                                                                             host_ref,
                                                                             False,
                                                                             False))
                         for vm_ref in vm_ref_list]
            run_xapi_async_tasks(session, task_list)

            # Verify the VMs report a 'Running' power state
            log.debug(
                "Verrifying VM power control operations (suspend) for 'Running'")
            for vm_ref in vm_ref_list:
                if session.xenapi.VM.get_power_state(vm_ref) != 'Running':
                    raise Exception("ERROR: VM %s did not resume" % vm_ref)
                log.debug("VM %s is running after suspending" % vm_ref)
            log.debug("Verrification complete: All VMs have resumed")

            log.debug("Test (suspend) run %d of %d has completed successfully" %
                      (i + 1, 3))

            wait_for_vms_ips(session, vm_ref_list)

        rec = {}
        rec['info'] = ("VM suspend tests completed successfully")

        return rec

    def test_vm_relocation(self, session):
        """Creates a number of VMs and 'relocates' them between
        the master host and the master host"""
        vm_ref_list = self._setup_vms(session)
        for i in range(3):
            log.debug("Starting test (relocation) run %d of %d" % (i + 1, 3))

            # Make certain the VMs are available
            for vm_ref in vm_ref_list:
                check_vm_ping_response(
                    session, vm_ref, get_context_vm_mip(vm_ref))

            # Relocate all VMs
            log.debug("Relocating VMs: %s" % vm_ref_list)
            host_ref = get_pool_master(session)
            task_list = [(lambda x=vm_ref: session.xenapi.Async.VM.pool_migrate(x,
                                                                                host_ref,
                                                                                {'live': 'true'}))
                         for vm_ref in vm_ref_list]
            run_xapi_async_tasks(session, task_list)

            # Verify the VMs report a 'Running' power state
            log.debug(
                "Verrifying VM power control operations (relocation) for 'Running'")
            for vm_ref in vm_ref_list:
                if session.xenapi.VM.get_power_state(vm_ref) != 'Running':
                    raise Exception("ERROR: Unexpected power state")
                log.debug("VM %s is running after relocating" % vm_ref)
            log.debug(
                "Verrification complete: All VMs have been relocated and are running")

            log.debug("Test (relocation) run %d of %d has completed successfully" %
                      (i + 1, 3))

            wait_for_vms_ips(session, vm_ref_list)

        rec = {}
        rec['info'] = ("VM relocation tests completed successfully")

        return rec


class CrashDumpTestClass(testbase.OperationsTestClass):
    """Test class to verify crash dump is created and collectable properly."""

    def test_crashdump(self, session):
        """Check crashdump is created properly."""
        log.debug("Running Crashdump test.")

        test_class = self.config['test_class']
        test_method = self.config['test_method']
        self.control = test_method.get_control()
        log.debug("control info: %s" % self.control)

        ret = {}
        if not self.control:
            crash_beg_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log.debug("prepare to crash dump %s" % crash_beg_time)

            self.control = "crash;%s" % crash_beg_time
            self.set_control(ret, self.control)
            self.set_test_name(ret, "%s.%s" % (
                self.__class__.__name__, CrashDumpTestClass.test_crashdump.__name__))
            # save test before crash
            test_class.update([ret])
            test_class.save('test_run.conf')

            # crash master by default
            time.sleep(5)
            host_crash(self.session)

            # should not reach here
            log.debug("Current host did not reboot")

        if self.control.startswith("crash"):
            crash_beg_time = self.control.split(';')[1]
            if not crash_beg_time:
                raise Exception(
                    "Reboot flag is not persistent and does not include crash info. Does host restarted by forced crashdump?")

            crash_beg_time = datetime(
                *(time.strptime(crash_beg_time, "%Y-%m-%d %H:%M:%S")[0:6]))
            log.debug("host crashed at %s" % str(crash_beg_time))

            # Check new crashdump was created during host crash.
            crashdumps_all = retrieve_crashdumps(session)
            log.debug("available crashdumps: %s" % (str(crashdumps_all)))
            crashdumps_matching = [
                cd for cd in crashdumps_all if crash_beg_time < cd['timestamp']]
            log.debug("matched crashdump(s): %s" % (str(crashdumps_matching)))
            if not len(crashdumps_matching) == 1:
                raise Exception("Host didn't create crashdump properly. number of new crashdumps: %d" % len(
                    crashdumps_matching))

            self.set_info(ret, 'An additional crashdump was detected.')

        return ret
