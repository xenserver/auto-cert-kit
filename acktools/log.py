#!/usr/bin/python

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


import sys
import logging
import logging.handlers


def configure_log(name, path, to_stdout=True):
    log = logging.getLogger(name)
    log.setLevel(logging.DEBUG)

    try:
        fileh = logging.FileHandler(path)
        fileh.setLevel(logging.DEBUG)
        formatter = logging.Formatter(
            '%%(asctime)-8s %s: %%(levelname)-8s %%(filename)s:%%(lineno)-10d %%(message)s' % name)
        fileh.setFormatter(formatter)
        log.addHandler(fileh)
    except IOError, e:
        print "Error writing to file handler. Ignoring."
        print str(e)

    if to_stdout:
        try:
            sth = logging.StreamHandler(sys.__stdout__)
            sth.setLevel(logging.DEBUG)
            log.addHandler(sth)
        except IOError, e:
            print "Error writing to stdout handler. Ignoring."
            print str(e)

    return log


def release_log(log):
    if not log:
        return
    log.debug("Releasing all handlers from log.")
    while len(log.handlers):
        handler = log.handlers[0]
        if 'flush' in dir(handler):
            handler.flush()
        log.removeHandler(handler)
        handler.close()
