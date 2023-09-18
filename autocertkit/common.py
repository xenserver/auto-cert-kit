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

import os
import time
import subprocess
import uuid


SSH = '/usr/bin/ssh'
SCP = '/usr/bin/scp'
EXPECT = '/usr/bin/expect'
ACK_HOME = '/opt/xensource/packages/files/auto-cert-kit/'


def set_logger(logger):
    global log
    log = logger


def make_local_call(call, logging=True, std_out=subprocess.PIPE,
                    std_err=subprocess.PIPE, shell=False, timeout=None):
    """Function wrapper for making a simple call to shell"""
    if logging:
        log.debug(f"make_local_call: {call}")
    process = subprocess.Popen(call, stdout=std_out, stderr=std_err,
                               shell=shell, universal_newlines=True)
    stdout, stderr = process.communicate(timeout=timeout)
    res = {"returncode": process.returncode, "stdout": stdout.strip(),
           "stderr": str(stderr).strip()}
    if logging:
        log.debug("returncode: %d" % process.returncode)
        log.debug("stdout: %s" % str(stdout))
        log.debug("stderr: %s" % str(stderr))
        if res["returncode"] != 0:
            log.error(f"ERR: Could not make local call: {call}")

    return res


class SecureChannel:
    """Wrap of ssh and scp"""

    def __init__(self, ip, user, password, timeout=300):
        self.ip = ip
        self.user = user
        self.password = password
        self.timeout = timeout

    def _wrap_cmd(self, cmd):
        escape_cmd = cmd.replace('$', '\$')
        return fr'''{EXPECT} << EOF
set timeout {self.timeout}
spawn {escape_cmd}
expect {{
    "continue connecting (yes/no)?" {{send "yes\n"; exp_continue}}
    "password:" {{send "{self.password}\n"; exp_continue}}
    eof {{catch wait result; exit [lindex \$result 3]}}
    timeout {{exit 250}}
}}
EOF
'''

    def _wrap_ssh(self, cmd):
        return self._wrap_cmd(f'{SSH} {self.user}@{self.ip} {{ {cmd} }}')

    def run_cmd(self, cmd):
        """Run command simply and ignore stderr"""
        return make_local_call(self._wrap_ssh(cmd), shell=True, timeout=self.timeout)

    def run_cmd_ext(self, cmd):
        """Run command and capture stdout and stderr separately"""
        id = str(uuid.uuid4())
        fcmd = f'.ack_cmd.{id}'
        frc = f'.ack_rc.{id}'
        fout = f'.ack_out.{id}'
        ferr = f'.ack_err.{id}'

        with open(f'/tmp/{fcmd}', 'w') as f:
            f.write(cmd)
        self.put_file(f'/tmp/{fcmd}')

        self.run_cmd(fr'sh {fcmd} >{fout} 2>{ferr}; echo "$?" >{frc}')

        self.get_file(f'.ack_*.{id}', '/tmp/')
        contents = []
        for f in [frc, fout, ferr]:
            with open(f'/tmp/{f}', 'r') as f:
                contents.append(f.read().strip())

        self.run_cmd(fr'rm -f .ack_*.{id}')
        for f in [fcmd, frc, fout, ferr]:
            os.remove(f'/tmp/{f}')

        res = {'returncode': int(contents[0]), 'stdout': contents[1], 'stderr': contents[2]}
        log.debug(f'Real result: {res}')

        return res

    def _wrap_scp(self, src, dst):
        return self._wrap_cmd(f'{SCP} {src} {dst}')

    def put_file(self, src, dst=''):
        cmd = self._wrap_scp(src, f'{self.user}@{self.ip}:{dst}')
        return make_local_call(cmd, shell=True, timeout=self.timeout)

    def get_file(self, src, dst='.'):
        cmd = self._wrap_scp(f'{self.user}@{self.ip}:{src}', dst)
        return make_local_call(cmd, shell=True, timeout=self.timeout)


def ssh_command(ip, username, password, cmd_str, dbg_str=None, attempts=10, timeout=900):
    """execute an SSH command, return both exit code, stdout and stderr."""
    if dbg_str:
        log.debug(dbg_str)

    for i in range(0, attempts):
        log.debug("Attempt %d/%d: %s" % (i, attempts, cmd_str))

        try:
            result = SecureChannel(ip, username, password, timeout).run_cmd_ext(cmd_str)
        except Exception as e:
            log.debug("Exception: %s" % str(e))
            # Sleep before next attempt
            time.sleep(20)
        else:
            return result

    log.debug("Max attempt reached %d/%d" % (attempts, attempts))
    return {"returncode": -1, "stdout": "", "stderr": "An unkown error has occured!"}

