#!/usr/bin/python3

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

"""Module for checking the status of the kit. This will be of most interest
when the kit has rebooted in order to change it's backend, allowing automated clients
to keep track of progress."""

from test_report import *
import utils
import models
import os

TEST_FILE = "test_run.conf"
DEFAULT_RUN_LEVEL = 3
running = False


def get_process_strings():
    ps = subprocess.Popen(
        ['ps', 'aux'], stdout=subprocess.PIPE, universal_newlines=True).communicate()[0]
    process_strings = []
    for line in ps.split('\n'):
        if 'ack_cli.py' in line or 'test_runner.py' in line:
            process_strings.append(line)
    return process_strings


def check_for_process():
    process_strings = get_process_strings()
    my_pid = str(os.getpid())
    for line in process_strings:
        if my_pid in line:
            process_strings.remove(line)
    if process_strings:
        return True


def get_run_level():
    output = subprocess.Popen(
        ['/sbin/runlevel'], stdout=subprocess.PIPE).communicate()[0]
    _, level = output.split()
    return int(level)


def main():
    running = False
    uptime_seconds = utils.os_uptime()

    # Check for manifest file
    if not os.path.exists(TEST_FILE):
        print("4:Manifest file has not been created. Have run the kit? (Has an error occured?)")
        sys.exit(0)

    # Check for the python process
    if check_for_process():
        running = True

    # Check the XML file to find out how many tests have been run
    try:
        ack_run = models.parse_xml(TEST_FILE)
    except:
        print("5:An error has occured reading. %s" % TEST_FILE)
        sys.exit(1)

    p, f, s, w, r = ack_run.get_status()

    if w+r == 0:
        print("0:Finished (Passed:%d, Failed:%d, Skipped:%d)" % (p, f, s))
    elif not running and uptime_seconds <= 600 and r > 0:
        print("3:Server rebooting... (Passed:%d, Failed:%d, Skipped:%d, Waiting:%d, Running:%d)" % (
            p, f, s, w, r))
    elif not running and uptime_seconds > 600:
        print("1:Process not running. An error has occurred. (Passed:%d, Failed:%d, Skipped: %d, Waiting:%d, Running:%d)" % (
            p, f, s, w, r))
        sys.exit(1)
    else:
        perc = float(p + f + s) / float(w + r + p + f + s) * 100
        print("2:Running - %d%% Complete (Passed:%d, Failed:%d, Skipped:%d, Waiting:%d, Running:%d)" % (
            perc, p, f, s, w, r))


if __name__ == "__main__":
    main()
