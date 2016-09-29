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

SSHPORT = 22

# Symbols we want to export from the package.
__all__ = ["SSHSession",
           "SFTPSession",
           "SSHCommand",
           "SSH",
           "SSHread",
           "getPublicKey"]


def getPublicKey():
    filename = ".ssh/id_dsa.pub"
    f = file(filename, "r")
    data = f.read()
    f.close()
    return string.strip(data)


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
        for tries in range(3):
            self.trans = None
            try:
                self.connect(ip, username, password, timeout)
            except Exception, e:
                log.error(traceback.format_exc())
                desc = str(e)
                log.error("SSH exception %s" % (desc))
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
        self.reply = "SSH connection failed"
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


class SFTPSession(SSHSession):
    """An SFTP session guarded for target lockups."""

    def __init__(self,
                 ip,
                 log,
                 username="root",
                 timeout=300,
                 password=None,
                 nowarn=False):
        self.log = log
        self.log.debug("SFTP session to %s@%s" % (username, ip))
        self.ip = ip
        self.username = username
        self.timeout = timeout
        self.password = password
        self.nowarn = nowarn
        SSHSession.__init__(self,
                            ip,
                            log,
                            username=username,
                            timeout=timeout,
                            password=password,
                            nowarn=nowarn)
        try:
            # We do this rather than the simple trans.open_sftp_client() because
            # if we don't then we don't get a timeout set so we can hang
            # forever
            c = self.trans.open_channel("session")
            c.settimeout(timeout)
            c.invoke_subsystem("sftp")
            self.client = paramiko.SFTPClient(c)
        except:
            self.reply = "SFTP connection failed"
            self.toreply = 1
            self.close()

    def getClient(self):
        # This is UNSAFE - the client object may change if we auto reconnect!
        return self.client

    def check(self):
        # Check if the connection is still active, if not, try and re-open the
        # connection (this handles the case where the connection has dropped
        # due to a transient network error)...

        alive = True

        # First see if the transport is alive
        if not self.trans.is_active():
            alive = False
        else:
            try:
                d = self.client.listdir()
            except:
                alive = False

        if not alive:
            log.warn(
                "SFTP session appears to have gone away, attempting to reconnect...")
            self.__init__(self.ip,
                          self.log,
                          username=self.username,
                          timeout=self.timeout,
                          password=self.password,
                          nowarn=self.nowarn)

    def close(self):
        if self.client:
            try:
                self.client.close()
            except Exception, e:
                log.debug("SFTP close exception %s" % (str(e)))
        if self.trans:
            try:
                self.trans.close()
            except Exception, e:
                log.debug("SFTP trans close exception %s" % (str(e)))

    def copyTo(self, source, dest, preserve=True):
        log.debug("SFTP local:%s to remote:%s" % (source, dest))
        self.client.put(source, dest)
        if preserve:
            st = os.lstat(source)
            if preserve == True:
                self.client.chmod(dest, st.st_mode)
            self.client.utime(dest, (st.st_atime, st.st_mtime))

    def copyFrom(self, source, dest, preserve=True, threshold=None,
                 sizethresh=None):
        log.debug("SFTP remote:%s to local:%s" % (source, dest))
        self.check()
        st = self.client.stat(source)
        if threshold and st.st_mtime < threshold:
            log.debug("Skipping %s, too old" % (source))
            return
        elif sizethresh and st.st_size > long(sizethresh):
            log.debug("Skipping %s, too big (%u)" %
                      (source, st.st_size))
            return
        self.client.get(source, dest)
        if preserve:
            if preserve == True:
                os.chmod(dest, st.st_mode)
            os.utime(dest, (st.st_atime, st.st_mtime))

    def copyTreeTo(self, source, dest, preserve=True):
        """Recursive copy to the remote host

        source: local directory being root of the tree
        dest:   remote directory to be the new root of the tree
        """
        log.debug("SFTP recursive local:%s to remote:%s" %
                  (source, dest))
        self.check()
        source = os.path.normpath(source)
        dirs = os.walk(source)
        for dir in dirs:
            (dirname, dirnames, filenames) = dir
            # Create the remote directory
            dirname = os.path.normpath(dirname)
            relpath = dirname[len(source):]
            if len(relpath) > 0 and relpath[0] == "/":
                relpath = relpath[1:]
            targetpath = os.path.normpath(os.path.join(dest, relpath))
            try:
                self.client.lstat(targetpath)
                # Already exists
                if preserve == True:
                    self.client.chmod(targetpath, os.lstat(dirname).st_mode)
            except IOError, e:
                self.client.mkdir(targetpath, os.lstat(dirname).st_mode)
            # Copy all the files in
            for file in filenames:
                srcfile = os.path.join(dirname, file)
                dstfile = os.path.join(targetpath, file)
                st = os.lstat(srcfile)
                self.client.put(srcfile, dstfile)
                if preserve:
                    if preserve == True:
                        self.client.chmod(dstfile, st.st_mode)
                    self.client.utime(dstfile, (st.st_atime, st.st_mtime))

    def copyTreeFromRecurse(self, source, dest, preserve=True, threshold=None,
                            sizethresh=None):
        # make sure local destination exists
        if not os.path.exists(dest):
            os.makedirs(dest)
        if preserve:
            os.chmod(dest, self.client.lstat(source).st_mode)
        d = self.client.listdir(source)
        for i in d:
            try:
                dummy = self.client.listdir("%s/%s" % (source, i))
                isdir = True
            except:
                isdir = False
            if isdir:
                self.copyTreeFromRecurse("%s/%s" % (source, i),
                                         "%s/%s" % (dest, i),
                                         preserve=preserve,
                                         threshold=threshold,
                                         sizethresh=sizethresh)
            else:
                log.debug("About to copy %s/%s" % (source, i))
                st = self.client.stat("%s/%s" % (source, i))
                if threshold and st.st_mtime < threshold:
                    log.debug("Skipping %s/%s, too old" %
                              (source, i))
                elif sizethresh and st.st_size > long(sizethresh):
                    log.debug("Skipping %s/%s, too big (%u)" %
                              (source, i, st.st_size))
                else:
                    self.client.get("%s/%s" % (source, i),
                                    "%s/%s" % (dest, i))
                    if preserve:
                        if preserve == True:
                            os.chmod("%s/%s" % (dest, i), st.st_mode)
                        os.utime("%s/%s" % (dest, i),
                                 (st.st_atime, st.st_mtime))

    def copyTreeFrom(self, source, dest, preserve=True, threshold=None,
                     sizethresh=None):
        """Recursive copy from the remote host

        source: remote directory being root of the tree
        dest:   local directory to be the new root of the tree
        """
        log.debug("SFTP recursive remote:%s to local:%s" %
                  (source, dest))
        self.check()
        self.copyTreeFromRecurse(source,
                                 dest,
                                 preserve=preserve,
                                 threshold=threshold,
                                 sizethresh=sizethresh)

    def copyLogsFrom(self, pathlist, dest, threshold=None, sizethresh=None):
        """Copy any files or directory trees from pathlist remotely to
        dest locally"""
        log.debug("SFTP log fetch of %s to local:%s" %
                  (`pathlist`, dest))
        for p in pathlist:
            # Directory?
            log.debug("Trying to fetch %s." % (p))
            try:
                d = self.client.listdir(p)
                self.copyTreeFrom(p, "%s/%s" % (dest, os.path.basename(p)),
                                  preserve="utime", threshold=threshold,
                                  sizethresh=sizethresh)
            except:
                # File?
                try:
                    s = self.client.lstat(p)
                    self.copyFrom(p, "%s/%s" % (dest, os.path.basename(p)),
                                  preserve="utime", threshold=threshold,
                                  sizethresh=sizethresh)
                except:
                    pass

    def __del__(self):
        SSHSession.__del__(self)


class SSHCommand(SSHSession):
    """An SSH session guarded for target lockups."""

    def __init__(self,
                 ip,
                 command,
                 log,
                 username="root",
                 timeout=300,
                 password=None,
                 nowarn=False,
                 newlineok=False,
                 nolog=False,
                 ignoreExitCode=False):
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
        self.ignoreExitCode = ignoreExitCode
        if string.find(command, "\n") > -1 and not newlineok:
            log.debug("Command with newline: '%s'" % (command))
        try:
            self.client = self.open_session()
            self.client.settimeout(timeout)
            self.client.set_combine_stderr(True)
            self.client.exec_command(command)
            self.client.shutdown(1)
            self.fh = self.client.makefile()
        except Exception, e:
            self.reply = "SSH connection failed",
            self.toreply = 1
            self.close()

    def read(self, retval="code", fh=None):
        """Process the output and result of the command.

        @param retval: Whether to return the result code (default) or 
            stdout as a string.

            string  :   Return a stdout as a string.
            code    :   Return the result code. (Default). 

            If "string" is used then a failure results in an exception.

        """

        if self.toreply:
            if retval == "string":
                raise Exception(self.reply)
            return self.reply
        reply = ""

        while True:
            try:
                if fh:
                    output = self.fh.read(4096)
                else:
                    output = self.fh.readline()
            except socket.timeout:
                self.close()
                return "SSH timed out"
            if len(output) == 0:
                break
            if fh:
                fh.write(output)
            elif retval == "string":
                reply = reply + output
            if not self.nolog and not fh:
                self.log.debug(output)
        self.exit_status = self.client.recv_exit_status()

        # Local clean up.
        self.close()

        if retval == "code":
            return self.exit_status
        if self.exit_status == -1:
            return "SSH channel closed unexpectedly"
        elif (not self.exit_status == 0) and (not self.ignoreExitCode):
            return "SSH command exited with error (%s)" % (self.command)

        return reply

    def __del__(self):
        SSHSession.__del__(self)


def SSH(ip,
        command,
        username="root",
        timeout=300,
        retval="code",
        password=None,
        idempotent=False,
        nowarn=False,
        newlineok=False,
        getreply=True,
        nolog=False,
        outfile=None):
    tries = 0
    while True:
        tries = tries + 1
        log.debug("SSH %s@%s %s (attempt %u)" %
                  (username, ip, command, tries))
        try:
            s = SSHCommand(ip,
                           command,
                           username=username,
                           timeout=timeout,
                           password=password,
                           nowarn=nowarn,
                           newlineok=newlineok,
                           nolog=nolog)
            if outfile:
                try:
                    f = file(outfile, 'w')
                    reply = s.read(retval="code", fh=f)
                finally:
                    f.close()
                return reply
            elif getreply:
                reply = s.read(retval=retval)
                return reply
            else:
                return None
        except Exception, e:
            if tries >= 3 or not idempotent:
                raise e
            if string.find(str(e), "SSH command exited with error") > -1:
                raise e
            if not nowarn:
                log.debug("Retrying ssh connection %s@%s %s after %s"
                          % (username, ip, command, str(e)))
            time.sleep(5)


def SSHread(ip,
            command,
            log,
            username="root",
            timeout=300,
            password=None,
            idempotent=False,
            nowarn=False,
            newlineok=False):
    tries = 0
    while True:
        tries = tries + 1
        log.debug("SSH %s@%s %s (attempt %u)" %
                  (username, ip, command, tries))
        try:
            s = SSHCommand(ip,
                           command,
                           log,
                           username=username,
                           timeout=timeout,
                           password=password,
                           nowarn=nowarn,
                           newlineok=newlineok)
            reply = s.read(retval="string")
            return reply
        except Exception, e:
            if tries >= 3 or not idempotent:
                raise e
            if string.find(str(e), "SSH command exited with error") > -1:
                raise e
            if not nowarn:
                log.debug("Retrying ssh connection %s@%s %s after %s"
                          % (username, ip, command, str(e)))
            time.sleep(5)
