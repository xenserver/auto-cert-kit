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

import socket
import string
import sys
import os
import os.path
import traceback
import time
import gc
import paramiko
from utils import *

SSHPORT = 22


class SSHSession:

    def __init__(self,
                 ip,
                 log,
                 username="root",
                 timeout=300,
                 password=None,
                 nowarn=False):
        self.toreply = 0
        self.log = log
        self.debug = False
        self.trans = None
        for retry in range(3):
            self.trans = None
            try:
                self.connect(ip, username, password, timeout)
            except Exception, e:
                log.error(traceback.format_exc())
                desc = str(e)
                log.error("SSH retry %d exception %s" % (retry, desc))
                if string.find(desc, "Signature verification") > -1 or \
                        string.find(desc,
                                    "Error reading SSH protocol banner") > -1:
                    # Have another go
                    log.warn("Retrying SSH connection after '%s'" % (desc))
                    try:
                        self.close()
                    except:
                        pass
                    time.sleep(1)
                    continue
                elif string.find(desc, "Authentication failed") > -1:
                    self.reply = "SSH authentication failed"
                    self.toreply = 1
                    self.close()
                    break
                else:
                    # Probably a legitimate exception
                    pass
                self.reply = "SSH connection failed"
                self.toreply = 1
                self.close()
                break
            # If we get here we have successfully opened a connection
            return
        # Even after retry(s) we didn't get a connection
        self.reply = "SSH connection all tries failed"
        self.toreply = 1
        self.close()

    def connect(self, ip, username, password, timeout):
        self.log.debug("%s %s %s %d" % (ip, username, password, timeout))
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, SSHPORT))

        # Create SSH transport.
        self.trans = paramiko.Transport(sock)
        self.trans.set_log_channel("")

        # Negotiate SSH session synchronously.
        goes = 3
        while goes > 0:
            try:
                self.trans.start_client()
                goes = 0
            except Exception, e:
                goes = goes - 1
                if goes > 0:
                    self.log.debug("Retrying SSHSession connection %d" % goes)
                    time.sleep(10)
                else:
                    raise e

        # Load DSS key.
        k = None
        try:
            dsskey = ".ssh/id_dsa"
            k = paramiko.DSSKey.from_private_key_file(dsskey)
        except:
            pass

        # Authenticate session. No host key checking is performed.
        if password:
            if password == "<NOPASSWORD>":
                password = ""
            self.trans.auth_password(username, password)
        else:
            if not k:
                raise RuntimeError("No password given and no key read")
            self.log.debug("Using SSH public key %s" % (dsskey))
            self.trans.auth_publickey(username, k)
        if not self.trans.is_authenticated():
            raise RuntimeError("Problem with SSH authentication")

    def open_session(self):
        return self.trans.open_session()

    def close(self):
        if self.trans:
            self.trans.sock.shutdown(socket.SHUT_RDWR)
            self.trans.close()
            self.trans = None
            gc.collect()
            time.sleep(5)

    def __del__(self):
        self.close()


class SSHCommand(SSHSession):
    """An SSH session guarded for target lockups."""

    def __init__(self, ip, command, username, password, opt):
        log = opt['log']
        timeout = opt.get('timeout', 300)
        nowarn = opt.get('nowarn', False)
        nolog = opt.get('nolog', False)
        combine_stderr = opt.get('combine_stderr', False)

        self.log = log
        if not nolog:
            log.debug("ssh %s@%s %s" % (username, ip, command))
        SSHSession.__init__(self,
                            ip,
                            log,
                            username=username,
                            timeout=timeout,
                            password=password,
                            nowarn=nowarn)
        self.command = command
        self.nolog = nolog

        try:
            self.client = self.open_session()
            self.client.settimeout(timeout)
            self.client.set_combine_stderr(combine_stderr)
            self.client.exec_command(command)
            self.client.shutdown(1)
            self.hStdout = self.client.makefile()
            self.hStderr = None if combine_stderr else self.client.makefile_stderr()
        except Exception, e:
            self.reply = "SSH command executed failed: %s" % str(e),
            self.toreply = 1
            self.close()

    def read_file(self, inf, outf=None, label="stdout"):
        reply = ""
        while True:
            try:
                if outf:
                    output = inf.read(4096)
                else:
                    output = inf.readline()
            except socket.timeout:
                if not self.nolog:
                    self.log.error("Error: SSH read time out!")
                return reply

            if len(output) == 0:
                break
            if outf:
                outf.write(output)
            else:
                reply += output

            if not self.nolog:
                self.log.debug("%s: %s" %
                               (label, (output[:-1] if output and output[-1] == '\n' else output)))
        return reply

    def read(self, out_file=None, err_file=None):
        """Process the output and result of the command.
        @:param out_file/err_file: Whether to write stdout/stderr to the file
            None (Default) : just return stdout/stderr content
            Not None : write stdout/stderr content to the file, which is used for large content
        @:return dict including exit status, stdout and stderr
        """

        if self.toreply:
            raise Exception(self.reply)

        self.exit_status = self.client.recv_exit_status()
        if not self.nolog:
            self.log.debug("returncode: %d" % self.exit_status)
        self.stdout = self.read_file(self.hStdout, out_file)
        self.stderr = self.read_file(self.hStderr, err_file, label="stderr") \
            if self.hStderr else ""

        # Local clean up.
        self.close()

        return {"returncode": self.exit_status, "stdout": self.stdout, "stderr": self.stderr}

    def __del__(self):
        SSHSession.__del__(self)
