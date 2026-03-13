#!/usr/bin/env python3
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
"""
Droid VM Template Preparation Script (Rocky Linux)

Usage:
    python gen_vm_template.py <VM_IP>

This script performs 6 steps:
1. Pre-checks: Verify setup-scripts dir exists and VM is SSH-reachable
2. Copy setup-scripts to the VM via SSH/SCP
3. Run init-run.sh inside the VM (installs dependencies, configures firewall, etc.)
4. Reboot the VM and wait for SSH to come back
5. Find the VM UUID by IP (requires XenTools installed in VM)
6. Shut down and export the VM as vpx-dlvm.xva

Note: The generated XVA file must be manually copied to slave hosts.
"""

import os
import sys
import time
import argparse
from common import *

# Constants
ACK_DIR = "/opt/xensource/packages/files/auto-cert-kit"
SETUP_SCRIPTS_SRC = os.path.join(ACK_DIR, "setup-scripts")
REMOTE_SETUP_DIR = "/root/setup-scripts"
XVA_NAME = "vpx-dlvm.xva"
XVA_PATH = os.path.join(ACK_DIR, XVA_NAME)

DEFAULT_PASSWORD = "xenserver"
DEFAULT_USERNAME = "root"


def get_vm_uuid_by_ip(vm_ip):
    """Find VM UUID by its IP address using xe vm-list."""
    result = make_local_call(["xe", "vm-list", "params=uuid,networks", "--multiple"], logging=False)
    if result['returncode'] != 0:
        return None
    
    lines = result['stdout'].strip().split('\n')
    current_uuid = None
    current_networks = None
    
    for line in lines:
        line = line.strip()
        if line.startswith("uuid"):
            parts = line.split(":", 1)
            if len(parts) == 2:
                current_uuid = parts[1].strip()
        elif line.startswith("networks"):
            parts = line.split(":", 1)
            if len(parts) == 2:
                current_networks = parts[1].strip()
        elif line == "" and current_uuid and current_networks:
            if vm_ip in current_networks:
                return current_uuid
            current_uuid = None
            current_networks = None
    
    if current_uuid and current_networks and vm_ip in current_networks:
        return current_uuid
    
    return None


def wait_for_ssh(vm_ip, vm_pass, max_tries=60, interval=5):
    """Wait for SSH to become available on the VM."""
    print("Waiting for SSH on %s..." % vm_ip)
    for i in range(max_tries):
        try:
            result = ssh_command(vm_ip, DEFAULT_USERNAME, vm_pass, "echo ok")
            if result['returncode'] == 0:
                print("SSH is available on %s" % vm_ip)
                return True
        except Exception:
            pass
        time.sleep(interval)
    raise RuntimeError("Timeout waiting for SSH on %s" % vm_ip)


def main():
    parser = argparse.ArgumentParser(description="Prepare Droid VM template for ACK (Rocky Linux)")
    parser.add_argument("vm_ip", help="IP address of the VM")
    args = parser.parse_args()

    vm_ip = args.vm_ip
    vm_pass = DEFAULT_PASSWORD

    # Step 1: Pre-checks
    print("[1/6] Pre-checks")
    if not os.path.isdir(SETUP_SCRIPTS_SRC):
        raise RuntimeError("Cannot find setup scripts dir: %s" % SETUP_SCRIPTS_SRC)

    # Try SSH connection - if reachable, continue; otherwise fail
    try:
        wait_for_ssh(vm_ip, vm_pass, max_tries=10, interval=5)
    except RuntimeError as e:
        print("\n%s" % str(e))
        print("Troubleshooting tips:")
        print("  1. Check if VM is powered on: xe vm-list | grep <vm_name>")
        print("  2. Verify correct IP address for the VM")
        print("  3. Check network/firewall on VM host")
        print("  4. Make sure VM has network configured (DHCP or static IP)")
        sys.exit(1)

    # Step 2: Copy setup-scripts into VM
    print("[2/6] Copy setup-scripts into VM")
    channel = SecureChannel(vm_ip, DEFAULT_USERNAME, vm_pass, timeout=300)
    channel.run_cmd("rm -rf %s" % REMOTE_SETUP_DIR)
    result = channel.put_file(SETUP_SCRIPTS_SRC, "/root/")
    if result['returncode'] != 0:
        print("Error copying setup scripts: %s" % result['stderr'])
        sys.exit(1)

    # Step 3: Run Rocky init-run.sh inside VM
    print("[3/6] Run Rocky init-run.sh inside VM")
    channel.run_cmd("command -v semanage || dnf install -y policycoreutils-python-utils")
    channel.run_cmd("chmod +x %s/init-run.sh && bash %s/init-run.sh" % (REMOTE_SETUP_DIR, REMOTE_SETUP_DIR))
    print("init-run.sh completed")

    # Step 4: Reboot VM and wait for SSH
    print("[4/6] Reboot VM and wait for SSH back")
    channel.run_cmd("reboot")
    time.sleep(10)
    wait_for_ssh(vm_ip, vm_pass)

    # Step 5: Find VM UUID
    print("[5/6] Find VM UUID")
    vm_uuid = None

    # Try to get UUID from inside VM via /sys/hypervisor/uuid
    result = ssh_command(vm_ip, DEFAULT_USERNAME, vm_pass, "cat /sys/hypervisor/uuid")
    if result['returncode'] == 0 and result['stdout']:
        for line in result['stdout'].strip().split('\n'):
            line = line.strip()
            if len(line) == 36 and '-' in line:
                vm_uuid = line
                break

    # Try xe vm-list by IP
    if not vm_uuid:
        vm_uuid = get_vm_uuid_by_ip(vm_ip)

    # Ask user
    if not vm_uuid:
        print("\nCould not auto-detect VM UUID. Please run:")
        print("  xe vm-list | grep %s" % vm_ip)
        print("And provide the UUID:")
        vm_uuid = input("VM UUID: ").strip()

    if not vm_uuid or len(vm_uuid) != 36:
        print("Invalid UUID: %s" % vm_uuid)
        sys.exit(1)

    print("VM UUID: %s" % vm_uuid)

    # Step 6: Shutdown and export VM
    print("[6/6] Shutdown and export VM as %s" % XVA_NAME)
    result = make_local_call(["xe", "vm-param-get", "uuid=%s" % vm_uuid, "param-name=name-label"], logging=False)
    vm_name = result['stdout'].strip() if result['returncode'] == 0 else "unknown"
    print("Shutting down VM %s (%s)..." % (vm_name, vm_uuid))
    make_local_call(["xe", "vm-shutdown", "uuid=%s" % vm_uuid], logging=False)
    time.sleep(5)
    print("Exporting VM to %s..." % XVA_PATH)
    result = make_local_call(["xe", "vm-export", "vm=%s" % vm_uuid, "filename=%s" % XVA_PATH], logging=True)
    if result['returncode'] != 0:
        print("Export failed: %s" % result['stderr'])
        sys.exit(1)

    print("\n" + "="*60)
    print("SUCCESS: VM template exported to %s" % XVA_PATH)
    print("="*60)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted by user")
        sys.exit(1)
    except Exception as e:
        print("\nError: %s" % str(e))
        import traceback
        traceback.print_exc()
        sys.exit(1)