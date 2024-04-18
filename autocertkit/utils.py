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

"""A module for utility functions shared with multiple test cases"""
import subprocess
import datetime
import XenAPI
import sys
import time
import signal
from datetime import datetime

import os
import threading
import re
import json
import binascii
import socket
import struct
import ctypes

from common import *
sys.path.append("/opt/xensource/packages/files/auto-cert-kit/pypackages")
from acktools.net import route, generate_mac
import acktools.log

K = 1024
M = 1024 * K
G = 1024 * M

DROID_VM = 'droid_vm'
DEFAULT_PASSWORD = 'xenserver'
FOR_CLEANUP = "for_cleanup"
DROID_TEMPLATE_TAG = "droid_vm_template"
REBOOT_ERROR_CODE = 3
REBOOT_FLAG_FILE = "/opt/xensource/packages/files/auto-cert-kit/reboot"
LOG_NAME = "auto-cert-kit"
LOG_LOC = "/var/log/auto-cert-kit.log"

# Capability Tags
REQ_CAP = "REQ"
MULTICAST_CAP = "MULTICAST"
SRIOV_CAP = "SR-IOV"

# XCP minimum version with Multicast support
XCP_MIN_VER_WITH_MULTICAST = "2.3.0"  # XenServer 7.2

# XCP minimum version with SR-IOV support
XCP_MIN_VER_WITH_SRIOV = "2.6.0"  # XenServer 7.5

# XAPI States
XAPI_RUNNING_STATE = "Running"

# allow to use specific
vpx_dlvm_file = "vpx-dlvm.xva"

LSPCI = "/sbin/lspci"
ETHTOOL = "/sbin/ethtool"


def configure_logging():
    """Method for configuring Logging"""
    global log
    log = acktools.log.configure_log(LOG_NAME, LOG_LOC)


configure_logging()
set_logger(log)


def release_logging():
    """Release logging object."""
    if log:
        acktools.log.release_log(log)


def log_basic_info(session):
    log.info("Auto Cert Kit Version: %s" % get_ack_version(session))
    log.info("Host Software Version: %s" % get_xs_info(session))
    log.info("Kernel Version       : %s" % get_kernel_version(session))
    log.info("Host Hardware Devices:\n%s" % get_system_info_tabular(session))


def init_ack_logging(session, rotate=True):
    release_logging()
    if rotate:
        for host_ref in session.xenapi.host.get_all():
            call_ack_plugin(session, 'run_ack_logrotate', {}, host=host_ref)
    configure_logging()
    log_basic_info(session)


def os_uptime():
    with open('/proc/uptime', 'r') as f:
        uptime_seconds = float(f.readline().split()[0])
        return uptime_seconds


class TestCaseError(Exception):
    """A subclassed exception object, which is raised by any
    test failure"""

    def __init__(self, *args):
        self.value = args[0]
        Exception.__init__(self, *args)

    def __str__(self):
        return repr("TEST_CASE_ERROR: %s" % self.value)


class TimeoutFunctionException(Exception):
    """Exception to raise on a timeout"""

    def __init__(self, *args):
        self.value = args[0]
        Exception.__init__(self, *args)

    def __str__(self):
        return repr("TIMEOUT_EXCEPTION: %s" % self.value)


class ArgumentError(Exception):
    """Raised when a user provides incomplete or missing arguments"""

    def __init__(self, *args):
        Exception.__init__(self, *args)


class ConfigFileNotFound(Exception):
    """Raised when a user provides incomplete or missing arguments"""

    def __init__(self, *args):
        self.file_name = args[0]
        self.config = args[1]
        Exception.__init__(self, *args)

    def __str__(self):
        return repr("%s file not found: '%s'. Please re-specify." % (self.config, self.file_name))


class InvalidArgument(ArgumentError):
    """Raised when a value provided as an argument is invalid"""

    def __init__(self, *args):
        self.arg_name = args[0]
        self.value = args[1]
        self.possibles = args[2]

    def __str__(self):
        return repr("INVALID_ARGUMENT: Argument Name: %s, Provided Value: '%s', Possible Options: %s" % (self.arg_name, self.value, self.possibles))

# Exception Decorator


def log_exceptions(func):
    def decorated(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except XenAPI.Failure as e:
            log.error('%s: XenAPI.Failure: %s', func.__name__, str(e))
            raise
        except Exception as e:
            log.error('%s: %s: %s', func.__name__,
                      e.__class__.__name__, str(e))
            raise
    return decorated
#############################


def int_to_bin(x):
    if x == 0:
        return ''
    else:
        return int_to_bin(x / 2) + str(x % 2)


class IPv4Addr(object):
    """Class for storing information about IP address"""

    def __init__(self, ip, netmask, gateway):
        self.addr = ip
        self.netmask = netmask
        self.gateway = gateway

    @staticmethod
    def check_ip_format(ip):
        # check by socket which can cover most of cases
        IPv4Addr.aton(ip)

        if len(ip.split('.')) != 4:
            raise Exception(
                "The IP address %s is invalid with number of '.' is not 3"
                % ip)

        # check no prefix 0 in each byte part, e.g. 10.71.05.88
        for b in ip.split('.'):
            if len(b) > 1 and b[0] == '0':
                raise Exception(
                    "The IP address %s is invalid with redundant digit '0'"
                    % ip)

    @staticmethod
    def check_netwrok_mask(mask):
        n_m = IPv4Addr.aton(mask)
        bs_m = "{0:0>32b}".format(n_m)
        # check not interlaced (just 1s on the left and 0s on the right)
        # and not all 0, and not all 1
        if bs_m.lstrip('1').rstrip('0') or bs_m[0] != '1' or bs_m[-1] != '0':
            raise Exception(
                "The network mask %s (%s) is invalid" % (mask, bs_m))

    @staticmethod
    def check_special_ip(ip, mask):
        n_ip = IPv4Addr.aton(ip)
        n_m = IPv4Addr.aton(mask)
        n_mc = ctypes.c_uint(~n_m).value
        # check network ip with host part is all 0
        if n_mc & n_ip == 0:
            raise Exception(
                "The IP address %s (%s) is network ip" % (ip, mask))
        # check broadcast ip with host part is all 1
        if n_mc & n_ip == n_mc:
            raise Exception(
                "The IP address %s (%s) is broadcast ip" % (ip, mask))

    @staticmethod
    def split(ip, mask):
        n_ip = IPv4Addr.aton(ip)
        n_m = IPv4Addr.aton(mask)
        subnet = ctypes.c_uint(n_ip & n_m).value
        host = ctypes.c_uint(n_ip & ~n_m).value
        return (subnet, host)

    @staticmethod
    def aton(ip):
        try:
            return struct.unpack("!I", socket.inet_aton(ip))[0]
        except Exception as e:
            raise Exception(
                "The IP address %s is invalid, exception: %s"
                % (ip, str(e)))

    @staticmethod
    def ntoa(n_ip):
        try:
            return socket.inet_ntoa(struct.pack('!I', n_ip))
        except Exception as e:
            raise Exception(
                "The IP address 0x%x is invalid, exception: %s"
                % (n_ip, str(e)))

    @staticmethod
    def validate_netmask(mask):
        IPv4Addr.check_ip_format(mask)
        IPv4Addr.check_netwrok_mask(mask)

    @staticmethod
    def validate_ip(ip, mask):
        IPv4Addr.check_ip_format(ip)
        IPv4Addr.check_special_ip(ip, mask)

    @staticmethod
    def in_same_subnet(ip1, ip2, mask):
        return IPv4Addr.split(ip1, mask)[0] == IPv4Addr.split(ip2, mask)[0]

    def validate(self):
        IPv4Addr.validate_netmask(self.netmask)
        IPv4Addr.validate_ip(self.addr, self.netmask)
        IPv4Addr.validate_ip(self.gateway, self.netmask)
        assert(IPv4Addr.in_same_subnet(self.addr, self.gateway, self.netmask))

    def get_subnet_host(self):
        return IPv4Addr.split(self.addr, self.netmask)


def get_network_routes(session, host_ref, retry=6):
    """Return a list of NetRoute objects for this system"""
    attempt = retry
    while attempt:
        attempt -= 1
        try:
            results = call_ack_plugin(
                session, 'get_host_routes', {}, host=host_ref)
        except:
            log.debug("Failed. retrying. (retry=%d)" % attempt)
            time.sleep(10)

    routes = []

    # Create NetRoute objects
    for rec in results:
        route_obj = route.Route(**rec)
        routes.append(route_obj)

    return routes


class StaticIPManager(object):
    """Class for managing static IP address provided by
    the caller. Allows us to do simple 'leasing' operations"""

    def __init__(self, conf):
        self.conf = conf
        self.subnet, self.host_start = IPv4Addr.split(
            conf['ip_start'], conf['netmask'])
        _, self.host_end = IPv4Addr.split(conf['ip_end'], conf['netmask'])
        self.total_ips = self.host_end - self.host_start + 1
        self._reset()

    def _reset(self):
        self.ips = [False] * self.total_ips
        self.free_ips = self.total_ips
        self.last_used = -1

    def get_ip(self):
        """Return an unused IP object (if one exists)"""
        id = self._get_free()
        ip = IPv4Addr.ntoa(self.subnet + self.host_start + id)
        return IPv4Addr(ip, self.conf['netmask'], self.conf['gw'])

    def return_ip(self, ip):
        """For a given IP object, put it back into circulation for others to use"""
        self._put_free(ip.get_subnet_host()[1] - self.host_start)

    def _is_free(self, id):
        return not self.ips[id]

    def _set_free(self, id):
        self.ips[id] = False
        self.free_ips += 1

    def _set_used(self, id):
        self.ips[id] = True
        self.free_ips -= 1

    def _get_next_of(self, id):
        return (id + 1) % self.total_ips

    def _get_free(self):
        while self.free_ips > 0:
            self.last_used = self._get_next_of(self.last_used)
            if self._is_free(self.last_used):
                self._set_used(self.last_used)
                return self.last_used
        else:
            raise Exception(
                "Error: no more IP addresses to allocate! (%d in use)" % self.total_ips)

    def _put_free(self, id):
        if self._is_free(id):
            raise Exception(
                "Error: Should not free a unused IP address id: %d" % id)
        self._set_free(id)

    def release_all(self):
        """Return all of the IP addresses that are currently in use"""
        log.debug("Clearing in-use IP list.")
        self._reset()

    def available_ips(self):
        """Return number of unused IP in IP pool"""
        return self.free_ips


class IfaceStats(object):
    """Class object for representing network statistics associated
       with an ethernet interface"""

    # List of keys depended on by callers
    required_keys = ['rx_bytes', 'tx_bytes', 'arch']

    def __init__(self, iface, rec):
        setattr(self, 'iface', iface)
        self.validate_args(rec)

        # Load all key/values into the class as attributes
        for k, v in rec.items():
            try:
                setattr(self, k, int(v))
            except ValueError:
                setattr(self, k, str(v))

    def validate_args(self, rec):
        rec_keys = rec.keys()
        for key in self.required_keys:
            if key not in rec_keys:
                raise Exception("Error: could not find key '%s'" % key +
                                " in iface statistics record '%s'" % rec)


def is_64_bit(arch):
    """Check if platform type is 64 bit"""
    return arch in ['x86_64']


def value_in_range(value, min_v, max_v):
    """Establish whether a value lies between two numbers"""
    return min_v <= value <= max_v


def wrapped_value_in_range(value, min_v, max_v, wrap=4 * G):
    """The value is assumed to be wrapped at some point. The function
    must test whether the value falls within the expected range.
    e.g. if our range is between 15-25, but we wrap at 20, then the
    value '4' should be acceptable."""

    if value >= wrap:
        raise Exception("Error: the value is greater/equal than the wrap")

    if min_v > max_v:
        raise Exception("Error: min must be greated than max. %d %d" %
                        (min_v, max_v))

    if min_v - max_v >= wrap:
        raise Exception("Error: cannot accurately determine if value " +
                        "is in a range that is the space of a wrap")

    # This is a normal comparison opp
    if max_v < wrap:
        return value_in_range(value, min_v, max_v)

    # The range spans the wrap, there are two ranges we need
    # to check:
    #
    # 0------------y--------w
    # 0----z-----------------
    # We must check whether:
    #
    #  y > value < w or 0 > value > z

    min_v_wrapped = min_v % wrap
    max_v_wrapped = max_v % wrap

    # min_v_wrapped must be smaller (not equal)
    # if min_v_wrapped = max_v_wrapped then we must
    # accept a value that covers the entire range.
    if min_v_wrapped < max_v_wrapped:
        return value_in_range(value, min_v_wrapped, max_v_wrapped)
    else:
        pre_range = value_in_range(value, min_v_wrapped, wrap)
        post_range = value_in_range(value, 0, max_v_wrapped)

        return pre_range or post_range


class IperfTestStatsValidator(object):

    warn_threshold = 5
    error_threshold = 10

    def __init__(self, pre_stats, post_stats):
        setattr(self, 'pre', pre_stats)
        setattr(self, 'post', post_stats)

        assert pre_stats.arch == post_stats.arch
        setattr(self, 'arch', pre_stats.arch)

    def value_in_range(self, value, min_v, max_v):
        ret = value_in_range(value, min_v, max_v)
        if not ret and not is_64_bit(self.arch):
            log.debug("IfaceStats 32bit and value is not in rage."
                      "Try checking with wrapped value. (%s)" % self.arch)
            ret = wrapped_value_in_range(value, min_v, max_v, 4 * G)
        return ret

    def validate_bytes(self, sent_bytes, tcpdump_bytes, attr):
        pre_bytes = getattr(self.pre, attr)
        post_bytes = getattr(self.post, attr)

        low_lim = pre_bytes + sent_bytes
        warn_lim = low_lim + sent_bytes * self.warn_threshold / 100
        high_lim = low_lim + sent_bytes * self.error_threshold / 100
        # high_lim_wa is workaround for issue found in CP-27559
        high_lim_wa = low_lim + sent_bytes + sent_bytes * 2 * self.error_threshold / 100

        log.debug("pre_bytes = %d" % pre_bytes)
        log.debug("post_bytes = %d" % post_bytes)
        log.debug("sent_bytes = %d" % sent_bytes)
        log.debug("tcpdump_bytes = %d" % tcpdump_bytes)
        log.debug("low_lim = %d" % low_lim)
        log.debug("warn_lim = %d" % warn_lim)
        log.debug("high_lim = %d" % high_lim)
        log.debug("high_lim_wa = %d" % high_lim_wa)
        
        tcpdump_result_ok = False
        if sent_bytes != 0 and 0.95 <= tcpdump_bytes/sent_bytes <= 1.05:
            tcpdump_result_ok = True
            log.debug("tcpdump_bytes/sent_bytes = %f" % (tcpdump_bytes/sent_bytes))

        if post_bytes < low_lim:
            if tcpdump_result_ok:
                log.debug("Warning: tcpdump result is OK,"
                          "sent_bytes: %d, tcpdump_bytes: %d"
                          "but mismatch in expected number of bytes, "
                          "post_bytes %d is less than low_lim %d"
                          "Suggest to run the test again."
                          % (sent_bytes, tcpdump_bytes, post_bytes, low_lim))
            else:
                raise Exception("Error: mismatch in expected number of bytes, "
                                "post_bytes %d is less than low_lim %d"
                                % (post_bytes, low_lim))

        if post_bytes > high_lim_wa:
            if tcpdump_result_ok:
                log.debug("Warning: tcpdump result is OK,"
                          "sent_bytes: %d, tcpdump_bytes: %d"
                          "but mismatch in expected number of bytes, "
                          "post_bytes %d is greater than high_lim_wa %d"
                          "Suggest to run the test again."
                          % (sent_bytes, tcpdump_bytes, post_bytes, low_lim))
            else:
                raise Exception("Error: mismatch in expected number of bytes, "
                                "post_bytes %d is greater than high_lim_wa %d"
                                % (post_bytes, high_lim_wa))

        log.debug("OK. It's in acceptable number of bytes range, "
                  "post_bytes %d is among low_lim %d and high_lim_wa %d."
                  % (post_bytes, low_lim, high_lim_wa))
        return True


class Iface(object):
    """Class representing an ethernet interface"""

    required_keys = ["ip", "mask", "mac"]

    def __init__(self, rec):
        self.validate_rec(rec)

        for k, v in rec.items():
            setattr(self, k, v)

    def validate_rec(self, rec):
        for key in self.required_keys:
            if key not in rec.keys():
                raise Exception("Error: invalid input rec '%s'" % rec)


def get_local_xapi_session():
    """Login to Xapi locally. This will only work if this script is being run 
    on Dom0. For this, no credentials are required. Wait until session connected successfully."""
    for i in range(10):
        if i > 0:
            time.sleep(15)
        try:
            session = XenAPI.xapi_local()
            session.login_with_password("", "")
            return session
        except Exception as e:
            log.debug("Get xapi session error: '%s', retry: %d" % (e, i))
    else:
        raise e


def get_pool_master(session):
    """Returns the reference to host which is currently master
    over the pool which can be seen with the given session"""
    pool_ref = session.xenapi.pool.get_all()[0]
    host_ref = session.xenapi.pool.get_master(pool_ref)
    return host_ref


def _find_control_domain(session, host_ref):
    vm_recs = session.xenapi.VM.get_all_records()
    for vm_ref, vm_rec in vm_recs.items():
        if vm_rec['is_control_domain'] and vm_rec['resident_on'] == host_ref:
            return vm_ref
    raise Exception(
        "Unexpected error. Cannot find control domain on host %s" % host_ref)


def get_master_control_domain(session):
    master_ref = get_pool_master(session)
    return _find_control_domain(session, master_ref)


def get_slave_control_domain(session):
    slave_refs = get_pool_slaves(session)
    if not slave_refs:
        raise Exception(
            "Error: the test kit requires a pool of at least 2 hosts.")
    # Only care about the first slave reference
    return _find_control_domain(session, slave_refs[0])


def reboot_all_hosts(session):
    master = get_pool_master(session)
    hosts = session.xenapi.host.get_all()
    for host in hosts:
        session.xenapi.host.disable(host)
        if host != master:
            session.xenapi.host.reboot(host)
    session.xenapi.host.reboot(master)


def reboot_normally(session):
    log.debug("Reboot all hosts normally")
    reboot_all_hosts(session)
    try:
        # Just wait host reboot and do not exit immediately,
        # otherwise status.py will get wrong status then
        time.sleep(300)
        sys.exit(REBOOT_ERROR_CODE)
    except:
        log.debug("ACK exit normally")


def host_reboot(session):
    log.debug("Attempting to reboot the host")
    # Cleanup all the running vms
    pool_wide_cleanup(session)
    reboot_all_hosts(session)
    log.debug("Rebooted master")
    sys.exit(REBOOT_ERROR_CODE)


def host_crash(session, do_cleanup=False):
    """ Force crash master. The host will be rebooted once it crashes."""
    if do_cleanup:
        pool_wide_cleanup(session)

    # Synchronise XAPI DB to disk  before crash.
    session.xenapi.pool.sync_database()
    time.sleep(5)

    host = get_pool_master(session)
    log.debug("Crashing host: %s" % host)
    #call_ack_plugin(session, 'force_crash_host')
    cmd = 'echo s > /proc/sysrq-trigger; sleep 5; echo c > /proc/sysrq-trigger'
    cmd = binascii.hexlify(cmd.encode())
    call_ack_plugin(session, 'shell_run', {'cmd': cmd.decode()}, host)

    # Once it is successful, host will be crashed hence code should not reach
    # here.
    raise Exception("Failed to crash host.")


def retrieve_crashdumps(session, host=None, fromxapi=False):
    """Retrive all list of crashdump of master."""
    if not host:
        host = get_pool_master(session)
    cds = call_ack_plugin(session, 'retrieve_crashdumps', {
                          'host': host, 'from_xapi': str(fromxapi)})
    for cd in cds:
        cd['size'] = int(cd['size'])
        ts = cd['timestamp']
        if fromxapi:
            cd['timestamp'] = datetime(int(ts[:4]),  # year
                                       int(ts[4:6]),   # month
                                       int(ts[6:8]),   # day
                                       int(ts[9:11]),  # hour
                                       int(ts[12:14]),  # minute
                                       int(ts[15:17]))  # second
        else:
            cd['timestamp'] = datetime(int(ts[:4]),  # year
                                       int(ts[4:6]),   # month
                                       int(ts[6:8]),   # day
                                       int(ts[9:11]),  # hour
                                       int(ts[11:13]),  # minute
                                       int(ts[13:15]))  # second
    log.debug("Retained Crashdumps: %s" % str(cds))
    return cds


def get_pool_slaves(session):
    """Returns a list of references for each host in a pool
    which is not a pool master"""
    slaves = []
    hosts = session.xenapi.host.get_all()
    master_ref = get_pool_master(session)
    for host in hosts:
        if master_ref != host:
            slaves.append(host)
    return slaves


def get_xenserver_version(session):
    """Return the XenServer version (using the master host)"""
    master_ref = get_pool_master(session)
    software = session.xenapi.host.get_software_version(master_ref)
    return software['product_version']


def get_xcp_version(session):
    """Return the XCP version (using the master host)"""
    master_ref = get_pool_master(session)
    software = session.xenapi.host.get_software_version(master_ref)
    return software['platform_version']


def get_kernel_version(session):
    """Return kernel version using uname"""
    return call_ack_plugin(session, 'get_kernel_version')


def eval_expr(expr, val):
    """Evaluate an expression against a provided value.
    Expressions should be in the form '<condition> <value>'"""
    log.debug("Eval Expr: %s %s" % (expr, val))
    arr = expr.split()
    if len(arr) > 3:
        raise Exception("Could not evaluate expression. " +
                        "Format is incorrect: %s" % expr)

    condition = arr[0]
    test_val = ' '.join(arr[1:])

    if condition == ">":
        res = val > test_val
    elif condition == "<":
        res = val < test_val
    elif condition == "=":
        res = val == test_val
    elif condition == "!=":
        res = val != test_val
    elif condition == ">=":
        res = val >= test_val
    elif condition == "<=":
        res = val <= test_val
    else:
        raise Exception("Specified condition is not yet supported for comparison: %s" %
                        condition)
    return res


def create_network(session, name_label, description, other_config):
    """Method for creating a XAPI network"""
    net_ref = session.xenapi.network.create({'name_label': name_label,
                                             'description': description,
                                             'other_config': other_config})
    oc = session.xenapi.network.get_other_config(net_ref)
    oc[FOR_CLEANUP] = "true"
    session.xenapi.network.set_other_config(net_ref, oc)
    return net_ref


def create_nic_bond(session, network, nics, mac='', mode='balance-slb'):
    """Creates a bond of type mode between two PIFs and returns 
    the network reference"""
    if len(nics) != 2:
        raise Exception("Expected two PIFs, received %s" % len(nics))
    log.debug("About to create bond between PIFs %s in mode %s" % (nics, mode))
    net_ref = session.xenapi.Bond.create(network, nics, mac, mode)
    log.debug("Bond %s is created." % net_ref)
    oc = session.xenapi.Bond.get_other_config(net_ref)
    oc[FOR_CLEANUP] = "true"
    session.xenapi.Bond.set_other_config(net_ref, oc)
    return net_ref


def get_pifs_by_device(session, device, hosts=[]):
    """Using device name (e.g. eth0) return a reference to the PIF that 
    is plugged into the master"""
    if hosts == []:
        hosts = session.xenapi.host.get_all()
    pifs = []
    for host in hosts:
        pifs = pifs + session.xenapi.host.get_PIFs(host)
    results = []
    for pif in pifs:
        if session.xenapi.PIF.get_physical(pif) \
                and (session.xenapi.PIF.get_device(pif) == device):
            results.append(pif)

    if len(results) > 0:
        return results
    raise TestCaseError("""No Ethernet device named %s 
                        can be found on host(s) %s""" %
                        (device, hosts))


def get_physical_pifs(session, pifs):
    res = []
    for pif in pifs:
        pif_rec = session.xenapi.PIF.get_record(pif)
        if pif_rec['physical']:
            res.append(pif)
        elif pif_rec['bond_master_of']:
            for bond in pif_rec['bond_master_of']:
                bond_pifs = session.xenapi.Bond.get_slaves(bond)
                res = res + get_physical_pifs(session, bond_pifs)
        elif pif_rec['VLAN_master_of'] != 'OpaqueRef:NULL':
            log.debug("VLAN PIF found: %s." % pif_rec)
            vlan_obj = session.xenapi.VLAN.get_record(
                pif_rec['VLAN_master_of'])
            res = res + \
                get_physical_pifs(session, [vlan_obj['tagged_PIF']])
        else:
            raise Exception(
                "Error: %s is not physical, bond or VLAN" % pif_rec)
    return res


def get_physical_devices_by_network(session, network):
    """Taking a network, enumerate the list of physical devices attached 
    to each component PIF. This may require some unwrapping (e.g. bonds)
    to determine all the consituent physical PIFs."""
    pifs = session.xenapi.network.get_PIFs(network)
    physical_pifs = get_physical_pifs(session, pifs)

    devices = []
    for pif in physical_pifs:
        device = session.xenapi.PIF.get_device(pif)
        if device not in devices:
            devices.append(device)

    if not devices:
        raise Exception("Error: no PIFs for network %s" % network)

    if len(devices) > 1:
        log.debug("More than one device for network %s: %s" % (network,
                                                               devices))
    return devices


def filter_pif_devices(session, devices):
    """Return non management devices from the set of devices
    defined by a user."""
    res = []
    management_device = get_pool_management_device(session)

    for device in devices:
        if device != management_device:
            res.append(device)

    if not res:
        raise TestCaseError("""Couldn't find a non-manamgement 
                                interfaces from those supplied""")
    return res


def get_equivalent_devices(session, device):
    devices = get_master_network_devices(session)
    ifaces = [dev['Kernel_name']
              for dev in devices if device['PCI_id'] == dev['PCI_id']]
    log.debug("Equivalent devices for %s: %s" % (device, ifaces))
    return ifaces


def has_sriov_cap(session, device):
    master_ref = get_pool_master(session)
    pifs_ref = get_pifs_by_device(session, device, [master_ref])
    caps = session.xenapi.PIF.get_capabilities(pifs_ref[0])
    return 'sriov' in caps


def enable_vf(session, device, host, network_label):
    pifs_ref = get_pifs_by_device(session, device, [host])
    net_ref = create_network(session, network_label, '', {})
    net_sriov_ref = session.xenapi.network_sriov.create(pifs_ref[0], net_ref)
    # no "other_config" field for FOR_CLEANUP

    return (net_ref, net_sriov_ref)


def get_test_sriov_network(session, network_label):
    networks = session.xenapi.network.get_all()
    for net in networks:
        label = session.xenapi.network.get_name_label(net)
        if label == network_label:
            return net

    return None


def is_vf_disabled(session):
    cmd = "%s | grep 'Virtual Function' | wc -l" % LSPCI
    cmd = binascii.hexlify(cmd.encode())
    sum = 0
    for host in session.xenapi.host.get_all():
        res = call_ack_plugin(session, 'shell_run', {'cmd': cmd.decode()}, host)
        res = res.pop()
        log.debug("Found %s VF on host %s" % (res["stdout"], str(host)))
        sum += int(res["stdout"]) if int(res["returncode"]) == 0 else 1
    log.debug("Found total %d VF" % sum)

    return sum == 0


def get_vf_driver_info(session, host, vm_ref, mip, device):
    cmd = "%s -i %s" % (ETHTOOL, device)
    log.debug("get_vf_driver_info: %s" % cmd)
    cmd = binascii.hexlify(cmd.encode())
    res = call_ack_plugin(session, 'shell_run',
                          {'cmd': cmd.decode(), 'vm_ref': vm_ref, 'mip': mip,
                           'username': 'root', 'password': DEFAULT_PASSWORD},
                          host)
    ret = {}
    filter_re = re.compile(r"(?P<key>driver|version|bus-info): (?P<value>.*)")
    for line in res.pop()['stdout'].split('\n'):
        # line sample: "driver: e1000e"
        match = filter_re.match(line)
        if match:
            ret[match.group("key")] = match.group("value")

    return ret


def get_management_network(session):
    networks = session.xenapi.network.get_all()
    for network in networks:
        pifs = session.xenapi.network.get_PIFs(network)
        for pif in pifs:
            if session.xenapi.PIF.get_management(pif):
                return network

    raise Exception("ERROR: No management network found!")


def get_management_interface(session, host):
    # this is for backward compatibility.
    # host.get_management_interface is added in XenServer 6.1
    # pif = session.xenapi.host.get_management_interface(host)
    for pif in session.xenapi.host.get_PIFs(host):
        if session.xenapi.PIF.get_management(pif):
            return pif

    raise Exception("ERROR: No management interface found!")


def create_vlan(session, pif_ref, network_ref, vlan_id):
    """Create a VLAN PIF from an existing physical PIF on the specified
    network"""
    log.debug("About to create_vlan")
    return session.xenapi.VLAN.create(pif_ref, str(vlan_id), network_ref)


def brand_vm(session, vm_ref, brand=DROID_VM):
    """Take a VM, or template and brand it with a key in other_config"""
    oc = session.xenapi.VM.get_other_config(vm_ref)
    oc[brand] = 'True'
    session.xenapi.VM.set_other_config(vm_ref, oc)


def convert_to_template(session, vm_ref):
    """Convert a VM to a template"""
    return session.xenapi.VM.set_is_a_template(vm_ref, True)


def create_vif(session, device, network, vm, mac=''):
    """Method for creating a XAPI Virtual Interface"""
    return session.xenapi.VIF.create({'device': device,
                                      'network': network,
                                      'VM': vm,
                                      'MAC': mac,
                                      'MTU': '1504',
                                      'other_config': {},
                                      'qos_algorithm_type': '',
                                      'qos_algorithm_params': {}})


def create_vif_on_vm_network(session, vm_ref, network_ref, device=0, wipe=True, mac=None):
    """Remove VIFs plugged into a VM, and create a new
    VIF and plug it in for a particular network"""

    if wipe:
        # 1. Remove all existings VIFs
        vif_refs = session.xenapi.VM.get_VIFs(vm_ref)
        log.debug("Existing VIFs %s" % vif_refs)

        for vif_ref in vif_refs:
            log.debug("Unplug and destroy VIF %s" % vif_ref)

            if session.xenapi.VM.get_power_state(vm_ref) == "Running":
                log.debug("Unplugging VIF... %s" % vif_ref)
                session.xenapi.VIF.unplug(vif_ref)
            log.debug("Destroing VIF... %s" % vif_ref)
            session.xenapi.VIF.destroy(vif_ref)

    log.debug("Create a new VIF for VM")
    log.debug("Network ref = %s" % network_ref)
    # 2. Create a new VIF attached to the specified network reference
    mac_tmp = mac if mac else generate_mac()
    vif_ref = create_vif(session, str(device),
                         network_ref, vm_ref, mac=mac_tmp)

    if session.xenapi.VM.get_power_state(vm_ref) == "Running":
        log.debug("Plug VIF %s" % vif_ref)
        session.xenapi.VIF.plug(vif_ref)

    return (vif_ref, device, mac_tmp)


def make_vm_noninteractive(session, vm_ref):
    """Set PV args to ensure the Demo VM boots up automatically,
    without requring a user to add a password"""
    session.xenapi.VM.set_PV_args(vm_ref, 'noninteractive')


def should_timeout(start, timeout):
    """Method for evaluating whether a time limit has been met"""
    return time.time() - start > float(timeout)


def _get_control_domain_ip(session, vm_ref, device='xenbr0'):
    """Return the IP address for a specified control domain"""
    if not session.xenapi.VM.get_is_control_domain(vm_ref):
        raise Exception("Specified VM is not a control domain")

    host_ref = session.xenapi.VM.get_resident_on(vm_ref)
    return call_ack_plugin(session, 'get_local_device_ip', {'device': device},
                           host_ref)


"""
To simply test, a context dict is used to record global information for test case
context:
    'vms': {vm_ref: {'mif': (interface, mac, ip),
                     'ifs': [(interface, mac, ip), ...]} }
    'networks': {net_ref: {'vifs': {vif_ref: (interface, mac, ip), ...}, 
                           'pifs': {},
                           'bridge': {} }
                           
  where
    mif: management interface
    ifs: all interfaces
"""


def init_context():
    clean_context()


def get_context():
    global __context
    return __context


def clean_context():
    global __context
    __context = {'vms': {}, 'arp_mode': '0'}
    return __context


def get_context_vms():
    return get_context()['vms']


def get_context_vm_mif(vm_ref):
    return get_context_vms()[vm_ref]['mif']


def set_context_vm_mif(vm_ref, mif):
    vms = get_context_vms()
    if vm_ref not in vms:
        vms[vm_ref] = {}
    vms[vm_ref]['mif'] = mif


def get_context_vm_mip(vm_ref):
    return get_context_vm_mif(vm_ref)[2]


def get_context_vm_ifs(vm_ref):
    return get_context_vms()[vm_ref]['ifs']


def set_context_vm_ifs(vm_ref, ifs):
    vms = get_context_vms()
    if vm_ref not in vms:
        vms[vm_ref] = {}
    vms[vm_ref]['ifs'] = ifs


def get_context_arp_mode():
    return get_context()['arp_mode']


def set_context_arp_mode(mode='0'):
    get_context()['arp_mode'] = mode


def get_context_test_ifs(vm_ref):
    mdevice = get_context_vm_mif(vm_ref)[0]
    return [test_if for test_if in get_context_vm_ifs(vm_ref) if test_if[0] != mdevice]


def get_management_vif(session, vm_ref):
    network = get_management_network(session)
    for vif in session.xenapi.VM.get_VIFs(vm_ref):
        if session.xenapi.VIF.get_network(vif) == network:
            return vif
    return None


def disable_vm_static_ip_service(session, mip):
    cmd = """systemctl stop static-ip; systemctl disable static-ip; systemctl status static-ip; """
    """rm -f /etc/sysconfig/network-scripts/ifcfg-eth*; """
    ssh_command(mip, 'root', DEFAULT_PASSWORD, cmd, attempts=1, timeout=60)


def get_vm_vif_ifs(session, vm_ref):
    """Get vm interfaces information (vif, mac, ip) from xenstore vif records"""
    ifs = {}
    dom_root = "/local/domain/%s" % str(session.xenapi.VM.get_domid(vm_ref))

    cmd = 'xenstore-ls -f %s | grep -E "%s/device/vif/[0-9]+/mac|%s/attr/vif/[0-9]+/ipv4/[0-9]+"' % (
        dom_root, dom_root, dom_root)
    args = binascii.hexlify(cmd.encode())
    res = call_ack_plugin(session, 'shell_run', {'cmd': args.decode()},
                          session.xenapi.VM.get_resident_on(vm_ref))
    res = res.pop()
    if int(res["returncode"]) != 0:
        log.debug("Failed to get vm interfaces from xenstore.")
        return ifs

    re_mac = re.compile(
        r"""^%s/device/vif/(?P<device>[0-9]+)/mac\s*=\s*"(?P<mac>.*)"$""" % dom_root)   # NOSONAR
    re_ip = re.compile(
        r"""^%s/attr/vif/(?P<device>[0-9]+)/ipv4/(?P<index>[0-9]+)\s*=\s*"(?P<ip>.*)"$""" % dom_root)   # NOSONAR
    for line in res["stdout"].split('\n'):
        m = re_mac.match(line)
        if m:
            device, mac = m.groups()
            if device not in ifs:
                ifs[device] = {"vif": device, "mac": "", "ip": ""}
            ifs[device]["mac"] = mac
            continue
        m = re_ip.match(line)
        if m:
            device, _, ip = m.groups()
            if device not in ifs:
                ifs[device] = {"vif": device, "mac": "", "ip": ""}
            ifs[device]["ip"] = ip

    return ifs


def wait_for_vm_mip(session, vm_ref, timeout=300):
    """Wait for vm management interface ready"""
    mvif = get_management_vif(session, vm_ref)
    mdevice = session.xenapi.VIF.get_device(mvif)
    mmac = session.xenapi.VIF.get_MAC(mvif)
    log.debug("VM %s: management device %s, mac %s" % (vm_ref, mdevice, mmac))

    start = time.time()
    i = 0
    while time.time() - start < float(timeout):
        log.debug("Trying to retrieve VM management IP address - Attempt %d" % i)
        ifs = get_vm_vif_ifs(session, vm_ref)
        log.debug("VM %s has these vif IPs %s" % (vm_ref, ifs))

        for _, f in ifs.items():
            if f["mac"] == mmac and f["ip"]:
                log.debug("Got management ip: %s" % f["ip"])
                set_context_vm_mif(vm_ref, ['', mmac, f["ip"]])
                return f

        i = i + 1
        time.sleep(5)

    raise Exception("""Timeout has been exceeded waiting for management IP
                     address of VM to be returned %s """ % str(timeout))


def wait_for_vm_ips(session, vm_ref, mip, timeout=300):
    """Wait for vm all interfaces ready"""
    vif_count = len(session.xenapi.VM.get_VIFs(vm_ref))
    host_ref = session.xenapi.VM.get_resident_on(vm_ref)
    start = time.time()
    i = 0
    while time.time() - start < float(timeout):
        log.debug("Trying to retrieve VM all IP address - Attempt %d" % i)
        ifs = get_vm_interface(session, host_ref, vm_ref, mip)
        log.debug("VM %s has these interface IPs %s" % (vm_ref, ifs))

        if len(ifs) >= vif_count and "" not in [f[2] for _, f in ifs.items()]:
            set_context_vm_ifs(
                vm_ref, [[f[0], f[1], f[2].split('/')[0]] for _, f in ifs.items()])
            mif = get_context_vm_mif(vm_ref)
            mdevices = [f[0] for _, f in ifs.items() if f[1] == mif[1]]
            set_context_vm_mif(vm_ref, [mdevices[0], mif[1], mif[2]])
            return ifs

        i = i + 1
        time.sleep(5)

    raise Exception("""Timeout has been exceeded waiting for all IP
                     address of VM to be returned %s """ % str(timeout))


def wait_for_vms_ips(session, vm_refs):
    """Wait for multiple vms all interfaces ready"""
    for vm_ref in vm_refs:
        mif = wait_for_vm_mip(session, vm_ref)
        wait_for_vm_ips(session, vm_ref, mif['ip'])


def _is_link_up(statedict):
    """Evaluate current operstate, carrier and link from dict."""

    if statedict['link'] == 'yes' and statedict['carrier'] == 'running' and statedict['operstate'] == 'up':
        return True
    return False


def wait_for_linkstate(session, device, state, host_ref=None, timeout=60):
    """Wait for interface to be a given state."""

    args = {'device': device}
    start = time.time()
    while not should_timeout(start, timeout):
        results = call_ack_plugin(
            session, 'get_local_device_linkstate', args, host_ref)
        cur_state = results[0]
        log.debug("Current linkstate of %s on host %s is %s." %
                  (device, host_ref, cur_state))
        if state.lower() == 'up' and _is_link_up(cur_state):
            return
        if state.lower() == 'down' and not _is_link_up(cur_state):
            return

        time.sleep(2)

    raise Exception("Timeout has been exceeded waiting for %s on %s changed to %s"
                    % (device, host_ref, state))


def get_vm_ips(session, vm_ref):
    guest_metrics_ref = session.xenapi.VM.get_guest_metrics(vm_ref)
    if guest_metrics_ref == "OpaqueRef:NULL":
        return {}
    networks = session.xenapi.VM_guest_metrics.get_networks(guest_metrics_ref)
    res = {}
    for k, v in networks.items():
        if k.endswith('ip'):
            res["eth%s" % (k.replace('/ip', ''))] = v
    return res


def ping(vm_ip, dst_vm_ip, interface, packet_size=1400,
         count=20, username="root", password=DEFAULT_PASSWORD):
    """Function for executing ping instruction via SSH to vm_ip.
    The ping command is then set against the interface specified,
    and directed at the dst_vm_ip given. If the packet is larger
    than the default, also run MTU discovery"""

    if packet_size > 1400:
        cmd_str = "ping -I %s -s %d -c %d -M do %s" % \
            (interface, packet_size, count, dst_vm_ip)
    else:
        cmd_str = "ping -I %s -s %d -c %d %s" % \
            (interface, packet_size, count, dst_vm_ip)
    log.debug("Ping: %s" % cmd_str)
    result = ssh_command(vm_ip, username, password,
                         cmd_str, attempts=10)["stdout"].split('\n')
    log.debug("Results= %s" % result)
    for line in result:
        log.debug("SSH Line: %s" % line)
        if 'transmitted' in line:
            return line
    raise TestCaseError("""Error: Unexpected response 
                       from ping, to transmission statistics: %s"""
                        % result)


def ping_with_retry(session, vm_ref, mip, dst_vm_ip, interface, timeout=20, retry=15):
    loss_re = re.compile(
        """.* (?P<loss>[0-9]+)% packet loss, .*""", re.S)  # NOSONAR

    cmd_str = "ping -I %s -w %d %s" % (interface, timeout, dst_vm_ip)
    cmd = binascii.hexlify(cmd_str.encode())
    for i in range(retry):
        log.debug("ping_with_retry %d/%d: %s" % (i, retry, cmd_str))

        if session.xenapi.VM.get_is_control_domain(vm_ref):
            args = {'cmd': cmd.decode()}
        else:
            args = {'vm_ref': vm_ref, 'mip': mip,
                    'username': 'root',
                    'password': DEFAULT_PASSWORD,
                    'cmd': cmd.decode()}
        res = call_ack_plugin(session, 'shell_run', args,
                              session.xenapi.VM.get_resident_on(vm_ref))
        result = res.pop()["stdout"]

        match = loss_re.match(result)
        if match and int(match.group("loss")) == 0:
            log.debug("Ping is successful completely, network is ready")
            return True

    log.debug("Warning: Ping is not successful completely, network has not been yet ready in %d seconds"
              % (timeout * retry))
    return False


def plug_pif(session, pif):
    """ Plug given pif"""
    log.debug("Plugging PIF: %s" % pif)
    session.xenapi.PIF.plug(pif)


def unplug_pif(session, pif):
    """Unplug a PIF"""
    if session.xenapi.PIF.get_disallow_unplug(pif):
        log.debug("PIF: %s is disallowed to unplug. Change setting." % pif)
        session.xenapi.PIF.set_disallow_unplug(pif, False)
    log.debug("Unplugging PIF: %s" % pif)
    session.xenapi.PIF.unplug(pif)


def destroy_pif(session, pif):
    """Unplug and destroy pif"""
    unplug_pif(session, pif)
    session.xenapi.PIF.destroy(pif)


def destroy_vm_vdi(session, vm_ref, timeout=60):
    # Check that the VDI is not in-use
    vbd_refs = session.xenapi.VM.get_VBDs(vm_ref)
    for vbd_ref in vbd_refs:
        vdi_ref = session.xenapi.VBD.get_VDI(vbd_ref)
        log.debug("Destroying VDI %s" % vdi_ref)
        try:
            start = time.time()
            ops_list = session.xenapi.VDI.get_allowed_operations(vdi_ref)
            while 'destroy' not in ops_list:
                time.sleep(2)
                ops_list = session.xenapi.VDI.get_allowed_operations(vdi_ref)
                if should_timeout(start, timeout):
                    raise Exception("Cannot destroy VDI: VDI is still active")
            # If the VDI is free, try to destroy it. Should pass the exception
            # catch if it is a NULL VDI reference.
            session.xenapi.VDI.destroy(vdi_ref)
        except XenAPI.Failure as exn:
            if exn.details[0] == 'HANDLE_INVALID':
                log.debug("Ignore XenAPI.Failure of HANDLE_INVALID")
            else:
                raise exn


def destroy_vm(session, vm_ref, timeout=60):
    """Checks powerstate of a VM, destroys associated VDIs, 
    and destroys VM once shutdown"""

    log.debug("Destroying VM: %s" % vm_ref)

    # If there is an on going operation, give some time to finish.
    start = time.time()
    cur_oper = session.xenapi.VM.get_current_operations(vm_ref)
    while len(cur_oper):
        log.debug("Found %s operations in action." % str(cur_oper))
        time.sleep(5)
        if should_timeout(start, 15):
            break
        cur_oper = session.xenapi.VM.get_current_operations(vm_ref)

    start = time.time()
    power_state = session.xenapi.VM.get_power_state(vm_ref)
    cur_oper = session.xenapi.VM.get_current_operations(vm_ref)
    while power_state != 'Halted' or len(cur_oper) > 0:
        log.debug("VM is %s with %s in action." % (power_state, str(cur_oper)))
        if should_timeout(start, timeout):
            raise Exception("Failed to stop VM or VM is not in right state. (VM: %s, power_state: %s)" % (
                vm_ref, power_state))
        log.debug("Trying shutting down VM: %s" % vm_ref)
        # Due to timing issue this may fail as it tries to shutdown halted VM.
        try:
            session.xenapi.VM.hard_shutdown(vm_ref)
        except Exception as e:
            log.error(str(e))
            log.debug(
                "Failed to hard shutdown VM. Trying again in a few seconds.")
        time.sleep(5)

        power_state = session.xenapi.VM.get_power_state(vm_ref)
        cur_oper = session.xenapi.VM.get_current_operations(vm_ref)

    log.debug("VM %s is ready to be removed." % vm_ref)

    destroy_vm_vdi(session, vm_ref, timeout)

    # Finally, destroy the VM
    log.debug("Destroying VM %s" % vm_ref)
    session.xenapi.VM.destroy(vm_ref)


def pool_wide_cleanup(session, tag=FOR_CLEANUP):
    """This function will look for all the object with a given tag,
    and remove them as part of a cleanup operation"""
    log.debug("**Performing pool wide cleanup...**")
    pool_wide_vm_cleanup(session, tag)
    need_reboot = pool_wide_network_sriov_cleanup(session, tag)
    pool_wide_network_cleanup(session, tag)
    pool_wide_host_cleanup(session)

    return need_reboot


def host_cleanup(session, host):
    # Check routes
    routes = get_network_routes(session, host)
    cur_route_table = route.RouteTable(routes)

    oc = session.xenapi.host.get_other_config(host)

    # Load in default routes
    default_route_key = 'default_routes'
    default_route_list = []
    if default_route_key in oc.keys():
        default_routes = eval(oc[default_route_key])    # NOSONAR
        for rec in default_routes:
            route_obj = route.Route(**rec)
            default_route_list.append(route_obj)

    default_route_table = route.RouteTable(default_route_list)
    missing_routes = default_route_table.get_missing(cur_route_table)

    dom0_ref = _find_control_domain(session, host)
    for missing_route in missing_routes:
        log.debug("Missing route: %s. Attempting to add to host %s" %
                  (missing_route.get_record(), host))

        args = {'vm_ref': dom0_ref,
                'dest_ip': missing_route.get_dest(),
                'device': missing_route.get_iface(),
                'gw': missing_route.get_gw(),
                'mask': missing_route.get_mask()}
        call_ack_plugin(session, 'add_route', args, host)

    log.debug("host cleanup is complete.")


def pool_wide_host_cleanup(session):
    hosts = session.xenapi.host.get_all()

    for host in hosts:
        host_cleanup(session, host)


def pool_wide_vm_dom0_cleanup(session, tag, vm, oc):
    # Cleanup any routes that are lying around
    keys_to_clean = []
    for k, v in oc.items():
        if k.startswith('route_clean_'):
            # Call plugin
            call_ack_plugin(session, 'remove_route',
                            {
                                'vm_ref': vm,
                                'dest_ip': v,
                            })
            keys_to_clean.append(k)

    if keys_to_clean:
        for key in keys_to_clean:
            del oc[key]

        session.xenapi.VM.set_other_config(vm, oc)


def pool_wide_vm_cleanup(session, tag):
    """Searches for VMs with a cleanup tag, and destroys"""
    vms = session.xenapi.VM.get_all()
    for vm in vms:
        oc = session.xenapi.VM.get_other_config(vm)
        if tag in oc:
            destroy_vm(session, vm)
            continue

        if session.xenapi.VM.get_is_control_domain(vm):
            pool_wide_vm_dom0_cleanup(session, tag, vm, oc)


def pool_wide_network_sriov_cleanup(session, tag):
    """Searches for network sriov, and destroys"""

    if get_xcp_version(session) < XCP_MIN_VER_WITH_SRIOV:
        return False

    sriov_nets = session.xenapi.network_sriov.get_all()
    for network in sriov_nets:
        # no "other_config" field for FOR_CLEANUP, so cleanup all
        session.xenapi.network_sriov.destroy(network)

    need_reboot = not is_vf_disabled(session)
    return need_reboot


def pool_wide_network_host_pif_cleanup(session, tag):
    for host in session.xenapi.host.get_all():
        for pif in session.xenapi.host.get_PIFs(host):
            oc = session.xenapi.PIF.get_other_config(pif)
            if oc.pop(tag, None):
                log.debug("Pif to cleanup: %s from host %s" % (pif, host))
                call_ack_plugin(session, 'flush_local_device',
                                {'device': session.xenapi.PIF.get_device(pif)},
                                host=host)
                session.xenapi.PIF.set_other_config(pif, oc)


def pool_wide_network_cleanup(session, tag):
    """Searches for networks with a cleanup tag, and
    destroys if found"""
    bonds = session.xenapi.Bond.get_all()
    for bond in bonds:
        if tag in session.xenapi.Bond.get_other_config(bond):
            session.xenapi.Bond.destroy(bond)
    networks = session.xenapi.network.get_all()
    for network in networks:
        if tag in session.xenapi.network.get_other_config(network):
            pifs = session.xenapi.network.get_PIFs(network)
            log.debug("Pifs to cleanup: %s from network %s" % (pifs, network))
            for pif in pifs:
                destroy_pif(session, pif)
            session.xenapi.network.destroy(network)
        elif session.xenapi.network.get_MTU(network) != '1500':
            set_network_mtu(session, network, '1500')
    pool_wide_network_host_pif_cleanup(session, tag)


def get_pool_management_device(session):
    """Returns the device used for XAPI mangagment"""
    device = None
    pifs = session.xenapi.PIF.get_all()
    for pif in pifs:
        if session.xenapi.PIF.get_management(pif):
            device_name = session.xenapi.PIF.get_device(pif)
            if device:
                if device_name != device:
                    raise TestCaseError(
                        """Error: Different device names are marked as management. Check that there are no residual bonds.""")
            else:
                device = device_name
    return device


def get_module_names(name_filter):
    """Returns a list of modules which can be seen in the callers scope,
    filtering their names by the given filter."""
    modules = []
    # Get all of the modules names currently in scope
    for module in sys.modules.keys():
        # Apply filter
        if name_filter in module:
            modules.append(module)
    return modules


def droid_template_import(session, host_ref, sr_uuid):
    """Import the droid template into the specified SR"""
    # Note, the filename should be fully specified.
    args = {'sr_uuid': sr_uuid, 'vpx_dlvm_file': vpx_dlvm_file}
    return call_ack_plugin(session, 'droid_template_import', args, host=host_ref)


def get_local_sr(session, host):
    """Returns the ref object the local SR on the master host"""
    all_pbds = session.xenapi.PBD.get_all_records()
    all_srs = session.xenapi.SR.get_all_records()
    for pbd_ref, pbd_rec in all_pbds.items():
        if host in pbd_rec['host']:
            for sr_ref, sr_rec in all_srs.items():
                if 'Local storage' in sr_rec['name_label'] and pbd_rec['SR'] in sr_ref:
                    return sr_ref
    raise Exception("No local SR attached to the master host")


def assert_sr_connected(session, sr_ref, host_ref):
    """Assert that a given SR is connected to a host"""
    pbds = session.xenapi.SR.get_PBDs(sr_ref)
    for pbd in pbds:
        if session.xenapi.PBD.get_host(pbd) == host_ref:
            log.debug("SR %s connected to host %s" % (session.xenapi.SR.get_uuid(
                sr_ref), session.xenapi.host.get_name_label(host_ref)))
            return True
    return False


def find_storage_for_host(session, host_ref, exclude_types=['iso', 'udev']):
    """Given a host reference, return available storage"""
    srs = session.xenapi.SR.get_all()

    # Find relevent SRs based on whether they're connected to host
    rel_srs = [sr for sr in srs
               if assert_sr_connected(session, sr, host_ref) and
               session.xenapi.SR.get_type(sr) not in exclude_types]

    log.debug("Available SRs for host '%s': '%s'" % (host_ref, rel_srs))

    log.debug("Host: %s" % session.xenapi.host.get_name_label(host_ref))
    for sr in rel_srs:
        log.debug("SR: %s" % session.xenapi.SR.get_name_label(sr))
    return rel_srs


def import_droid_vm_template(session, host_ref, creds=None):
    """Import VM template from Dom0 for use in tests"""
    sr_refs = find_storage_for_host(session, host_ref)

    if not sr_refs:
        raise Exception(
            "Error: could not find any available SRs for host '%s'" % host_ref)

    sr_ref = sr_refs.pop()
    log.debug("Importing droid VM to %s for use on host %s" %
              (session.xenapi.SR.get_name_label(sr_ref),
               session.xenapi.host.get_name_label(host_ref)))

    sr_uuid = session.xenapi.SR.get_uuid(sr_ref)
    vm_uuid = droid_template_import(session, host_ref, sr_uuid)
    vm_ref = session.xenapi.VM.get_by_uuid(vm_uuid)
    convert_to_template(session, vm_ref)
    brand_vm(session, vm_ref, DROID_TEMPLATE_TAG)
    session.xenapi.VM.set_name_label(vm_ref, 'Droid VM')
    time.sleep(5)
    return vm_ref


def find_droid_templates(session):
    """Returns a list of droid VM template refs"""
    refs = []
    vms = session.xenapi.VM.get_all_records()
    for ref, rec in vms.items():
        if DROID_TEMPLATE_TAG in rec['other_config'] \
                and rec['is_a_template']:
            refs.append(ref)

    log.debug("find_droid_templates: found refs: '%s'" % refs)

    return refs


def get_vm_vdis(session, vm_ref):
    vbds = session.xenapi.VM.get_VBDs(vm_ref)
    vdis = [session.xenapi.VBD.get_VDI(vbd) for vbd in vbds]
    return [vdi for vdi in vdis if vdi != "OpaqueRef:NULL"]


def assert_can_boot_here(session, vm_ref, host_ref):
    vdis = get_vm_vdis(session, vm_ref)

    req_srs = list(set([session.xenapi.VDI.get_SR(vdi) for vdi in vdis]))
    log.debug("VM %s requires SRs '%s'" % (vm_ref, req_srs))

    for sr_ref in req_srs:
        if not assert_sr_connected(session, sr_ref, host_ref):
            return False

    log.debug("VM %s can boot on host %s" % (vm_ref, host_ref))
    return True


def prepare_droid_vm_template(session, host_ref, creds=None):
    """Prepare droid vm template, import it if not existing"""
    log.debug("About to prepare droid vm template for host %s" % host_ref)

    templates = [template for template in find_droid_templates(session)
                 if assert_can_boot_here(session, template, host_ref)]

    if templates:
        # Any of the templates will do
        return templates.pop()
    else:
        log.debug("No droid vm template exists - import one")
        # Else - if no templates exist
        return import_droid_vm_template(session, host_ref, creds)


def run_xapi_async_tasks(session, funcs, timeout=300):
    """Execute a list of async functions, only returning when
    all of the tasks have completed."""
    task_refs = []

    i = 0
    for f in funcs:
        # Create a tuple with an index so that returned results
        # can keep the correct ordering.
        task_refs.append((i, f()))
        i = i + 1

    start = time.time()

    results = []
    while task_refs:
        idx, ref = task_refs.pop(0)  # take the first item off
        log.debug("Current Task: %s" % ref)
        status = session.xenapi.task.get_status(ref)
        if status == "success":
            log.debug("%s has finished" % ref)
            result = session.xenapi.task.get_result(ref)

            log.debug("Result = %s" % result)
            if result.startswith('<value>'):
                results.append((idx, result.split('value')[1].strip('</>')))
            else:
                # Some Async calls have no return value
                results.append((idx, result))
        elif status == "failure":
            # The task has failed, and the error should be propogated upwards.
            raise Exception("Async call failed with error: %s" %
                            session.xenapi.task.get_error_info(ref))
        else:
            log.debug("Task Status: %s" % status)
            # task has not finished, so re-attach to list
            task_refs.append((idx, ref))

        if should_timeout(start, timeout):
            # Change to TimeoutFunctionException to work-around CA-146164.
            # To avoid applying hotfixes, keeping this work-around.
            # raise Exception("Async calls took too long to complete!" +
            raise TimeoutFunctionException("Async calls took too long to complete!" +
                                           "Perhaps, the operation has stalled? %d" % timeout)
        time.sleep(1)

    # Sort the results in order of index
    results = sorted(results, key=lambda tup: tup[0])
    return [res for (_, res) in results]


def deploy_common_droid_vms_on_hosts(session, host_refs, network_refs, vm_count, sms=None, sr_ref=None):
    """Deploy vm_count common VMs on each host, here common means one network has only one vif,
    and management network vif device is 0, 1 for test network."""

    log.debug("Creating required VM(s)")

    host_vms = {}
    all_vms = []
    host_vm_list = []
    for host in host_refs:
        vms = import_droid_vms(session, host, vm_count)
        host_vms[host] = vms
        all_vms += vms
        host_vm_list += [(host, vm) for vm in vms]

    management_net_ref = network_refs[0] if len(network_refs) else None
    test_net_ref = network_refs[1] if len(network_refs) > 1 else None
    vm_vifs = {}
    if management_net_ref:
        for vm in all_vms:
            vm_vifs_info = init_droid_vm_mvif(
                session, vm, management_net_ref, sms, [0])
            vm_vifs[vm] = vm_vifs_info

    start_droid_vms(session, host_vm_list)

    if management_net_ref:
        for vm in all_vms:
            init_droid_vm_first_run(session, vm, vm_vifs[vm])

    if test_net_ref:
        for vm in all_vms:
            vm_vifs_info = init_droid_vm_vifs(
                session, vm, test_net_ref, sms, [1])
            vm_vifs[vm] = vm_vifs_info

    shutdown_droid_vms(session, all_vms)

    if test_net_ref:
        for vm in all_vms:
            create_vifs_for_droid_vm(session, vm, test_net_ref, vm_vifs[vm])

    start_droid_vms(session, host_vm_list)

    config_arp(session, all_vms)

    return host_vms


def deploy_two_droid_vms(session, network_refs, sms=None):
    """A utility method for setting up two common VMs, one on the master host, and one on slave host"""
    master = get_pool_master(session)
    slave = get_pool_slaves(session)[0]
    host_vms = deploy_common_droid_vms_on_hosts(session,
                                                [master, slave], network_refs, 1, sms)
    return host_vms[master][0], host_vms[slave][0]


def import_droid_vms(session, host_ref, count=1, label="Droid"):
    """Import count VM on host"""
    log.debug("Creating required VMs")
    vm_template_ref = prepare_droid_vm_template(session, host_ref)
    tasks = [lambda id=i: session.xenapi.Async.VM.clone(
        vm_template_ref, '%s_%d' % (label, id)) for i in range(1, count+1)]
    vm_refs = run_xapi_async_tasks(session, tasks)
    if len(vm_refs) != count:
        raise Exception(
            "Expect to clone %d vms - only got %d results" % (count, len(vm_refs)))

    for vm_ref in vm_refs:
        brand_vm(session, vm_ref, FOR_CLEANUP)
        session.xenapi.VM.set_is_a_template(vm_ref, False)
        make_vm_noninteractive(session, vm_ref)
    return vm_refs


def alloc_vifs_info(session, vm_ref, network_ref, sms, ids):
    """Alloc vifs information before creating"""
    if sms and network_ref in sms.keys() and sms[network_ref]:
        static_manager = sms[network_ref]
    else:
        static_manager = None

    id_vif_dict = {}
    for id in ids:
        ip, netmask, gw = "", "", ""
        if static_manager:
            ip_info = static_manager.get_ip()
            ip, netmask, gw = ip_info.addr, ip_info.netmask, ip_info.gateway
        id_vif_dict[id] = [id, generate_mac(), ip, netmask, gw]
    return id_vif_dict


def create_vifs_for_droid_vm(session, vm_ref, network_ref, vifs_info):
    """Setup VM network vifs"""
    log.debug("Setup vm %s vifs on network" % vm_ref)
    vifs_rec = []
    for id, vif_info in vifs_info.items():
        vif_info = create_vif_on_vm_network(
            session, vm_ref, network_ref, id, wipe=(id == 0), mac=vif_info[1])
        vifs_rec.append(vif_info)
    return vifs_rec


def init_vifs_ip_addressing(session, vm_ref, vifs_info):
    """Init VM vifs ip address by static or default dhcp"""
    for id, vif_info in vifs_info.items():
        device = "eth%d" % id
        ip, netmask, gw = vif_info[2], vif_info[3], vif_info[4]
        if ip:
            log.debug("Init VM %s device %s as static IP: %s, netmask: %s, gateway: %s" % (
                vm_ref, device, ip, netmask, gw))
            droid_set_static(session, vm_ref, 'ipv4', device, ip, netmask, gw)
        else:
            log.debug("Init VM %s device %s as default dhcp" %
                      (vm_ref, device))


def init_ifs_ip_addressing(session, vm_ref, vifs_info):
    """Init VM interfaces ip address by static or dhcp"""
    host_ref = session.xenapi.VM.get_resident_on(vm_ref)
    mip = get_context_vm_mip(vm_ref)
    for id, vif_info in vifs_info.items():
        device = "ethx%d" % id
        mac, ip, netmask, gw = vif_info[1], vif_info[2], vif_info[3], vif_info[4]
        if ip:
            dev_info = {'iface': device, 'mac': mac,
                        'ip': ip, 'netmask': netmask, 'gw': gw}
            droid_add_static_ifcfg(session, host_ref, vm_ref, mip, dev_info)
        else:
            droid_add_dhcp_ifcfg(session, host_ref, vm_ref, mip, device, mac)


def droid_add_static_ifcfg(session, host, vm_ref, mip, dev_info):
    """Set VM interface static ip in config file ifcfg-eth*"""
    cmd = '''echo "TYPE=Ethernet\nNAME=%s\nDEVICE=%s\nHWADDR=%s\n''' \
        '''IPADDR=%s\nNETMASK=%s\nGATEWAY=%s\nBOOTPROTO=none\nONBOOT=yes" ''' \
        '''> "%s/ifcfg-%s" ''' \
        % (dev_info['iface'], dev_info['iface'], dev_info['mac'], dev_info['ip'],
           dev_info['netmask'], dev_info['gw'], "/etc/sysconfig/network-scripts",
           dev_info['iface'])
    cmd = binascii.hexlify(cmd.encode())
    args = {'vm_ref': vm_ref,
            'mip': mip,
            'username': 'root',
            'password': DEFAULT_PASSWORD,
            'cmd': cmd.decode()}
    res = call_ack_plugin(session, 'shell_run', args, host)
    res = res.pop()
    if int(res["returncode"]) != 0:
        log.debug("Failed to add static ifcfg file")


def droid_add_dhcp_ifcfg(session, host, vm_ref, mip, iface, mac):
    """Set VM interface dhcp in config file ifcfg-eth*"""
    cmd = 'echo "NAME=%s\nDEVICE=%s\nHWADDR=%s\nBOOTPROTO=dhcp\nONBOOT=yes" > "%s/ifcfg-%s"' \
        % (iface, iface, mac, "/etc/sysconfig/network-scripts", iface)
    cmd = binascii.hexlify(cmd.encode())
    args = {'vm_ref': vm_ref,
            'mip': mip,
            'username': 'root',
            'password': DEFAULT_PASSWORD,
            'cmd': cmd.decode()}
    res = call_ack_plugin(session, 'shell_run', args, host)
    res = res.pop()
    if int(res["returncode"]) != 0:
        log.debug("Failed to add dhcp ifcfg file")


def droid_set_static(session, vm_ref, protocol, iface, ip, netmask, gw):
    """Set VM interface static ip by xenstore"""
    args = {'vm_uuid': session.xenapi.VM.get_uuid(vm_ref),
            'protocol': protocol,
            'iface': iface,
            'ip': ip,
            'netmask': netmask,
            'gateway': gw}
    return call_ack_plugin(session, 'droid_set_static_conf', args)


def init_droid_vm_mvif(session, vm_ref, network_ref, sms, ids=[0]):
    """Init VM management vif"""
    vm_vifs_info = alloc_vifs_info(session, vm_ref, network_ref, sms, ids)
    create_vifs_for_droid_vm(session, vm_ref, network_ref, vm_vifs_info)
    init_vifs_ip_addressing(session, vm_ref, vm_vifs_info)
    return vm_vifs_info


def init_droid_vm_first_run(session, vm_ref, vifs_info):
    """Init VM first run"""
    mip = get_context_vm_mip(vm_ref)
    # Install SSH Keys for Plugin operations
    call_ack_plugin(session, 'inject_ssh_key',
                    {'vm_ref': vm_ref, 'mip': mip, 'username': 'root',
                     'password': DEFAULT_PASSWORD})
    disable_vm_static_ip_service(session, get_context_vm_mip(vm_ref))
    init_ifs_ip_addressing(session, vm_ref, vifs_info)


def init_droid_vm_vifs(session, vm_ref, network_ref, sms, ids=[1]):
    """Init VM vifs"""
    vm_vifs_info = alloc_vifs_info(session, vm_ref, network_ref, sms, ids)
    init_ifs_ip_addressing(session, vm_ref, vm_vifs_info)
    return vm_vifs_info


def config_arp(session, vms):
    for vm in vms:
        call_ack_plugin(session, 'reset_arp',
            {'vm_ref': vm, 'mip': get_context_vm_mip(vm),
             'mode': get_context_arp_mode()})


def shutdown_droid_vms(session, vms, async_op=True):
    """Shutdown VMs"""

    log.debug("Shutdown required VMs")
    if async_op:
        try:
            run_xapi_async_tasks(session,
                                 [lambda x=vm_ref: session.xenapi.Async.VM.shutdown(x)
                                  for vm_ref in vms],
                                 180)

        except TimeoutFunctionException as e:
            log.debug("Timed out while shutdowning VMs: %s" % e)
    else:
        for i in vms:
            session.xenapi.VM.shutdown(i)


def start_droid_vms(session, vms, async_op=True):
    """Start VMs"""

    log.debug("Starting required VMs")
    if async_op:
        try:
            # Temporary setting time out to 3 mins to work around CA-146164.
            # The fix requires hotfixes, hence keeping this work-around.
            run_xapi_async_tasks(session,
                                 [lambda x=vm_ref, y=host_ref: session.xenapi.Async.VM.start_on(x, y, False, False)
                                  for host_ref, vm_ref in vms],
                                 180)

        except TimeoutFunctionException as e:
            # Temporary ignore time out to start VM.
            # If VM failed to start, test will fail while checking IPs.
            log.debug("Timed out while starting VMs: %s" % e)
            log.debug(
                "Async call timed out but VM may started properly. tests go on.")
    else:
        for host_ref, vm_ref in vms:
            session.xenapi.VM.start_on(vm_ref, host_ref, False, False)

    vm_refs = [vm_ref for _, vm_ref in vms]
    # Check the VMs are in the 'Running' state.
    wait_for_vms(session, vm_refs, XAPI_RUNNING_STATE)

    # Temp fix for establishing that a VM has fully booted before
    # continuing with executing commands against it.
    log.debug("Wait for IPs...")
    wait_for_vms_ips(session, vm_refs)
    log.debug("IP's retrieved...")


def wait_for_vms(session, vm_refs, power_state, timeout=60):
    """Wait for XAPI to mark each VM in the list as 'Running'"""
    log.debug("wait_for_vms: %s to reach state '%s'" % (vm_refs,
                                                        power_state))
    # Copy list
    vms = list(vm_refs)

    start = time.time()
    while vms and not should_timeout(start, timeout):
        vm = vms.pop()
        if session.xenapi.VM.get_power_state(vm) != power_state:
            vms.append(vm)

    if vms:
        # Our vm list should be empty if we have not timed out.
        for vm in vms:
            log.debug("VM not in '%s' state. Instead in '%s' state." %
                      (power_state, session.xenapi.VM.get_power_state(vm)))

        # We should raise an exception.
        raise Exception("VMs (%s) were not moved to the '%s' state in the provided timeout ('%d')" % (
            vms, power_state, timeout))


def setup_vm_for_sriov(session, vm_ref, vf_driver):
    mip = get_context_vm_mip(vm_ref)
    # management network is ready then install VF driver on VM, reboot VM again
    args = {'vm_ref': vm_ref,
            'mip': mip,
            'username': 'root',
            'password': DEFAULT_PASSWORD,
            'package': vf_driver[1],
            'driver_name': vf_driver[0]}
    call_ack_plugin(session, 'deploy_vf_driver', args)


def deploy_two_droid_vms_for_sriov_inter_host_test(session, vf_driver, network_refs, sms=None):
    """A utility method for setting up two VMs, one on the primary host for SR-IOV test network,
    and one on a slave host"""

    host_master_ref = get_pool_master(session)
    host_slave_ref = get_pool_slaves(session)[0]
    vm1_ref = import_droid_vms(
        session, host_master_ref, label='Droid_Sriov')[0]
    vm2_ref = import_droid_vms(session, host_slave_ref)[0]

    # config management network
    vm1_vifs_info = init_droid_vm_mvif(
        session, vm1_ref, network_refs[1][0], sms, [0])
    vm2_vifs_info = init_droid_vm_mvif(
        session, vm2_ref, network_refs[0][0], sms, [0])

    start_droid_vms(
        session, [(host_master_ref, vm1_ref), (host_slave_ref, vm2_ref)])

    init_droid_vm_first_run(session, vm1_ref, vm1_vifs_info)
    init_droid_vm_first_run(session, vm2_ref, vm2_vifs_info)

    setup_vm_for_sriov(session, vm1_ref, vf_driver)

    vm1_vifs_info = init_droid_vm_vifs(
        session, vm1_ref, network_refs[1][1], sms, [1])
    vm2_vifs_info = init_droid_vm_vifs(
        session, vm2_ref, network_refs[0][1], sms, [1])

    shutdown_droid_vms(session, [vm1_ref, vm2_ref])

    # config test networks
    create_vifs_for_droid_vm(
        session, vm1_ref, network_refs[1][1], vm1_vifs_info)
    create_vifs_for_droid_vm(
        session, vm2_ref, network_refs[0][1], vm2_vifs_info)

    start_droid_vms(
        session, [(host_master_ref, vm1_ref), (host_slave_ref, vm2_ref)])

    config_arp(session, [vm1_ref, vm2_ref])

    return vm1_ref, vm2_ref


def deploy_droid_vms_for_sriov_intra_host_test_vf_to_vf(session, vf_driver, network_refs, sms=None, vm_count=1, vf_count=1):
    """A utility method for setting up count VMs on primary host, with VFs evenly"""
    if len(network_refs[1]) != 2:
        raise Exception("length of network_refs[1] should be 2")
    management_net_ref, test_net_ref = network_refs[1]
    host_master_ref = get_pool_master(session)

    vf_num_list = [0] * vm_count
    for i in range(vf_count):
        vf_num_list[i % vm_count] += 1

    vm_list = import_droid_vms(
        session, host_master_ref, vm_count, 'Droid_Sriov')
    host_vm_list = [(host_master_ref, vm_ref) for vm_ref in vm_list]

    vm_vifs_dict = {}
    for vm_ref in vm_list:
        vm_vifs_info = init_droid_vm_mvif(
            session, vm_ref, management_net_ref, sms, [0])
        vm_vifs_dict[vm_ref] = vm_vifs_info

    start_droid_vms(session, host_vm_list, False)

    for vm_ref in vm_list:
        init_droid_vm_first_run(session, vm_ref, vm_vifs_dict[vm_ref])

        setup_vm_for_sriov(session, vm_ref, vf_driver)

        vf_ids = list(range(1, vf_num_list[vm_list.index(vm_ref)] + 1))
        vm_vifs_info = init_droid_vm_vifs(
            session, vm_ref, test_net_ref, sms, vf_ids)
        vm_vifs_dict[vm_ref] = vm_vifs_info

    shutdown_droid_vms(session, vm_list)

    vif_list = []
    vif_group = {}
    for vm_ref in vm_list:
        vifs_rec = create_vifs_for_droid_vm(
            session, vm_ref, test_net_ref, vm_vifs_dict[vm_ref])
        vif_refs = [vif_ref for vif_ref, _, _ in vifs_rec]
        vif_list += vif_refs
        vif_group[vm_ref] = vif_refs

    start_droid_vms(session, host_vm_list, False)

    config_arp(session, vm_list)

    return vm_list, vif_list, vif_group


def verify_vif_status(session, vifs, status):
    for vif in vifs:
        if session.xenapi.VIF.get_currently_attached(vif) != status:
            log.debug(
                "Error: vif %s currently-attached is not %s" % (vif, status))
            raise TestCaseError(
                'Error: SR-IOV test failed. VF currently-attached is incorrect')


def verify_vif_config(session, host, vif_group):
    for vm_ref, vifs in vif_group.items():
        mip = get_context_vm_mip(vm_ref)
        ifs = get_vm_interface(session, host, vm_ref, mip)
        log.debug("VM %s contains interface %s" % (vm_ref, ifs))

        # get all MAC
        all_mac = []
        for _, iface in ifs.items():
            all_mac.append(iface[1])

        for vif in vifs:
            vif_rec = session.xenapi.VIF.get_record(vif)
            log.debug("VIF %s device: %s, MAC: %s" %
                      (vif, vif_rec['device'], vif_rec['MAC']))

            # check MAC
            if vif_rec['MAC'] not in all_mac:
                log.debug("Error: MAC %s does not match any interface" %
                          vif_rec['MAC'])
                raise TestCaseError(
                    'Error: SR-IOV test failed. VF MAC does not match any interface')


class TimeoutFunction:
    """Wrapper class for providing a timemout for 
    the execution of a function"""

    def __init__(self, function, timeout, exception=''):
        self.timeout = timeout
        self.function = function
        self.exception = exception

    def handle_timeout(self, *args, **kwargs):
        raise TimeoutFunctionException(self.exception)

    def __call__(self, *args):
        old = signal.signal(signal.SIGALRM, self.handle_timeout)
        signal.alarm(self.timeout)
        try:
            result = self.function(*args)
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old)
        return result


def json_loads(json_data):
    def process_dict_keys(d):
        new_d = {}
        for key in d.keys():
            new_key = str(key.replace(" ", "_"))
            new_d[new_key] = d[key]
        return new_d

    def process_values(item):
        if isinstance(item, str):
            item = str(item)
        elif isinstance(item, list):
            for elem in item:
                elem = process_values(elem)
        elif isinstance(item, dict):
            item = process_dict_keys(item)
            for key in item.keys():
                item[key] = str(item[key])
        return item

    data = json.loads(json_data, object_hook=process_values)
    return [data] if isinstance(data, dict) else data


def call_ack_plugin(session, method, args={}, host=None, no_json_hook=False):
    if not host:
        host = get_pool_master(session)
    log.debug("About to call plugin '%s' on host '%s' with args '%s'" %
              (method, host, args))

    res = session.xenapi.host.call_plugin(host,
                                          'autocertkit',
                                          method,
                                          args)
    log.debug("Plugin Output: %s" % (
        "%s[...check plugin log for more]" % res[:1000] if res and len(res) > 1000 else res))
    if res:
        return json.loads(res) if no_json_hook else json_loads(res)
    return None


def get_hw_offloads(session, device):
    """We want to call the XAPI plugin on the pool
    master to return the offload capabilites of a device."""

    if call_ack_plugin(session, 'get_kernel_version').startswith('2.6'):
        res = call_ack_plugin(session, 'get_hw_offloads_from_core',
                              {'eth_dev': device})
    else:
        res = call_ack_plugin(session, 'get_hw_offloads',
                              {'eth_dev': device})

    return res[0]


def get_dom0_iface_info(session, host_ref, device):
    res = call_ack_plugin(session, 'get_local_device_info',
                          {'device': device},
                          host=host_ref)

    device_dict = res[0]
    return Iface(device_dict)


def get_vm_device_mac(session, vm_ref, device):
    """For a specified VM, obtain the MAC address of the specified dev"""
    if session.xenapi.VM.get_is_control_domain(vm_ref):
        # Handle Dom0 Case
        log.debug("get_vm_device_mac: VM (%s) device (%s)" % (vm_ref,
                                                              device))
        host_ref = session.xenapi.VM.get_resident_on(vm_ref)
        iface = get_dom0_iface_info(session, host_ref, device)
        return iface.mac
    else:
        # Handle the VM case
        vifs = session.xenapi.VM.get_VIFs(vm_ref)
        for vif in vifs:
            vif_rec = session.xenapi.VIF.get_record(vif)
            if vif_rec['device'] == device.replace('eth', ''):
                return vif_rec['MAC']
        raise Exception("Error: could not find device '%s' for VM '%s'" %
                        (device, vm_ref))


def get_dom0_device_name(session, vm_ref, net_ref):
    """Get dom0 device name of network"""
    vm_host = session.xenapi.VM.get_resident_on(vm_ref)
    pifs = session.xenapi.network.get_PIFs(net_ref)
    device_names = []
    for pif in pifs:
        if vm_host == session.xenapi.PIF.get_host(pif):
            device_names.append(session.xenapi.PIF.get_device(pif))
    log.debug("Got dom0 device names: %s" % device_names)
    if len(device_names) > 1:
        raise Exception("Error: expected only a single device " +
                        "name to be found in PIF list ('%s') " +
                        "Instead, '%s' were returned." %
                        (pifs, device_names))
    device_name = device_names.pop()
    return device_name.replace('eth', 'xenbr')


def wait_for_dom0_device_ip(session, vm_ref, device, static_manager):
    """Wait for dom0 device ip ready"""
    log.debug("Setup Dom0 IP on bridge %s" % device)
    args = {'device': device}

    if static_manager:
        args['mode'] = 'static'
        ip = static_manager.get_ip()
        args['ip_addr'] = ip.addr
        args['ip_netmask'] = ip.netmask
    else:
        args['mode'] = 'dhcp'

    host_ref = session.xenapi.VM.get_resident_on(vm_ref)
    res = call_ack_plugin(session,
                          'configure_local_device',
                          args,
                          host=host_ref)
    res = res.pop()
    set_context_vm_ifs(vm_ref, [[device, res['mac'], res['ip']]])
    set_context_vm_mif(vm_ref, ['', '', ''])


def get_vm_interface(session, host, vm_ref, mip):
    """Use ip command to get all interface (eth*) information"""

    # e.g. eth0: [eth0, ec:f4:bb:ce:91:9c, 10.62.114.80]
    ifs = {}

    # cmd output: "eth0: ec:f4:bb:ce:91:9c"
    cmd = """ip -o link | awk '{if($2 ~ /^eth/) print $2,$17}'"""
    res = ssh_command(mip, 'root', DEFAULT_PASSWORD, cmd)
    mac_re = re.compile(r"(?P<device>.*): (?P<mac>.*)")     # NOSONAR
    for line in res['stdout'].strip().split('\n'):
        match = mac_re.match(line)
        if match:
            device, mac = match.groups()
            ifs[device] = [device, mac, '']

    # cmd output: "eth0 10.62.114.80/21"
    cmd = """ip -o -f inet addr | awk '{if($2 ~ /^eth/) print $2,$4}'"""
    res = ssh_command(mip, 'root', DEFAULT_PASSWORD, cmd)
    ip_re = re.compile(r"(?P<device>.*) (?P<ip>.*)")    # NOSONAR
    for line in res['stdout'].strip().split('\n'):
        match = ip_re.match(line)
        if match:
            device, ip = match.groups()
            if device in ifs:
                ifs[device][2] = ip
            else:
                ifs[device] = [device, '', ip]

    return ifs


def get_iface_statistics(session, vm_ref, mip, iface):
    res = call_ack_plugin(session, 'get_iface_stats',
                          {'iface': iface,
                           'vm_ref': vm_ref,
                           'mip': mip})
    stats_dict = res[0]
    return IfaceStats(iface, stats_dict)


def set_hw_offload(session, device, offload, state):
    """Call the a XAPI plugin on the pool master to set
    the state of an offload path on/off"""
    log.debug("Device: %s - Set %s %s" % (device, offload, state))
    return call_ack_plugin(session, 'set_hw_offload',
                           {'eth_dev': device, 'offload': offload,
                            'state': state})


def set_nic_device_status(session, interface, status):
    """Function to set an ifconfig ethX interface up or down"""
    log.debug("Bringing %s network interface %s" % (status, interface))
    call_ack_plugin(session, 'set_nic_device_status',
                    {'device': interface, 'status': status})
    wait_for_linkstate(session, interface, status)
    time.sleep(5)


class TestThread(threading.Thread):
    """Threading class that runs a function"""

    def __init__(self, function, args=()):
        self.function = function
        self.args = args
        threading.Thread.__init__(self)

    def run(self):
        self.function(*self.args)


def create_test_thread(function, args=()):
    """Function for creating and starting a number of threads"""
    thread = TestThread(function, args)
    thread.start()
    return thread


def check_test_thread_status(threads):
    """Util function to check if test threads are still active,
    returns True if any are active, else False"""
    for thread in threads:
        if thread.isAlive():
            time.sleep(10)
            log.debug("Please be patient, the test is still running...")
            thread.join(20)
            return True
    return False


def get_system_info_hwinfo(session):
    return call_ack_plugin(session, 'get_system_info_hwinfo', no_json_hook=True)


def get_system_info_tabular(session):
    return call_ack_plugin(session, 'get_system_info_tabular')


def remove_invalid_keys(nics):
    # remove invalid keys of nic which violates xml, referring to
    # https://stackoverflow.com/questions/19677315/xml-tagname-starting-with-number-is-not-working
    for n in nics:
        for k, _ in list(n.items()):
            if k and k[0].isdigit():
                n.pop(k)
                log.debug("Remove invalid key %s from %s" % (k, n['PCI_name']))


def get_master_network_devices(session):
    nics = call_ack_plugin(session, 'get_network_devices')
    log.debug("Network Devices found on machine(Plugin): '%s'" % nics)

    remove_invalid_keys(nics)

    hwinfo_devs = get_system_info_hwinfo(session)
    if hwinfo_devs:
        nics_hw = hwinfo_devs['nics']
        log.debug("Network Devices found on machine(hwinfo): '%s'" % nics_hw)
        for n in nics:
            for nh in nics_hw:
                if n['PCI_name'] == "0000:%s" % nh['device_bus_id']:
                    n.update(nh)
    return nics


def get_local_storage_info(session):
    """Returns info about the local storage devices"""
    devices = call_ack_plugin(session, 'get_local_storage_devices')
    log.debug("Local Storage Devices found on machine: '%s'" % devices)
    return devices


def _convert_to_valid_xml_element_name(str1):
    if str1 and not str1[0].isalpha():
        str1 = "_" + str1
    str1 = str1.replace(":", "_")
    return str1


def _convert_dict_keys_to_valid_xml_tags(d):
    return {_convert_to_valid_xml_element_name(k): d[k] for k in d}


def get_xs_info(session):
    """Returns a limited subset of info about the XenServer version"""
    master_ref = get_pool_master(session)
    info = session.xenapi.host.get_software_version(master_ref)
    return _convert_dict_keys_to_valid_xml_tags(info)


def _get_type_and_value(entry):
    """Parse dmidecode entry and return key/value pair"""
    r = {}
    for l in entry.split('\n'):
        s = l.split(':')
        if len(s) != 2:
            continue
        r[s[0].strip()] = s[1].strip()
    return r


def copy_dict_items(src, dst, keys):
    """Copy src dict items to dst and rename with new key"""
    for skey, dkey in keys:
        if skey in src:
            dst[dkey] = src[skey]


def get_system_info(session):
    """Returns some information of system and bios."""

    rec = {}
    biosinfo = search_dmidecode(session, "BIOS Information")
    if biosinfo:
        entries = _get_type_and_value(biosinfo[0])
        copy_dict_items(entries, rec, [('Vendor', 'BIOS_vendor'),
                                       ('Version', 'BIOS_version'),
                                       ('Release Date', 'BIOS_release_date'),
                                       ('BIOS Revision', 'BIOS_revision')])

    sysinfo = search_dmidecode(session, "System Information")
    if sysinfo:
        entries = _get_type_and_value(sysinfo[0])
        copy_dict_items(entries, rec, [('Manufacturer', 'system_manufacturer'),
                                       ('Product Name', 'system_product_name'),
                                       ('Serial Number', 'system_serial_number'),
                                       ('UUID', 'system_uuid'),
                                       ('Version', 'system_version'),
                                       ('Family', 'system_family')])

    chassisinfo = search_dmidecode(session, "Chassis Information")
    if chassisinfo:
        entries = _get_type_and_value(chassisinfo[0])
        copy_dict_items(entries, rec, [('Type', 'chassis_type'),
                                       ('Manufacturer', 'chassis_manufacturer')])

    return rec


def set_dict_attributes(node, config):
    """Take a dict object, and set xmlnode attributes accordingly"""
    for k, v in config.items():
        node.setAttribute(str(k), str(v))


def get_xml_attributes(node):
    """Return the xml attributes of a node as a dictionary object"""
    attr = {}
    for k, v in node._get_attributes().items():
        attr[k] = v
    return attr


def to_bool(string):
    """Convert string value of true/false to bool"""
    return string.upper() == "TRUE"


def get_value(rec, key, default=""):
    if key in rec.keys():
        return rec[key]
    else:
        return default


def print_documentation(object_name):
    print("--------- %s ---------" % bold(object_name))
    classes = enumerate_test_classes()
    for test_class_name, test_class in classes:
        arr = (object_name).split('.')
        if test_class_name == object_name:
            # get the class info
            print(format(test_class.__doc__))
            print("%s: %s" % (bold('Prereqs'), test_class.required_config))
            sys.exit(0)
        elif len(arr) == 3 and ".".join(arr[:2]) == test_class_name:
            # get the method info
            print(format(getattr(test_class, arr[2]).__doc__))
            sys.exit(0)

    print("The test name specified (%s) was incorrect. Please specify the full test name." % object_name)
    sys.exit(0)


def bold(str):
    return "\033[1m%s\033[0;0m" % str


def format(str):
    """Format string to flow continuiously (without indents that have been inserted
    in order to make the docstring easy to follow"""
    arr = str.split('\n')
    arr = [item.strip() for item in arr]
    return " ".join(arr)


def enumerate_test_classes():
    import test_generators
    tg = test_generators.TestGenerator(
        'nonexistent_session', {}, 'nonexistent')
    return tg.get_test_classes()


def read_valid_lines(filename):
    """Utility function for returning alist of uncommented lines (as indicated by '#')."""
    comment_symbols = ['#']
    fh = open(filename, 'r')
    res = [line for line in [line.strip() for line in fh.readlines()]
           if len(line) > 0 and line[0] not in comment_symbols]
    fh.close()
    return res


def set_network_mtu(session, network_ref, mtu):
    """Utility function for setting a network's MTU. MTU should be a string"""
    session.xenapi.network.set_MTU(network_ref, str(mtu))
    pifs = session.xenapi.network.get_PIFs(network_ref)
    for pif in pifs:
        unplug_pif(session, pif)
        plug_pif(session, pif)


def intersection(lista, listb):
    """Return the intersection between two lists. Note,
    for duplicate values, each duplicate will be returned as 
    we merely check if item in lista, is in listb."""
    return [item for item in lista if item in listb]


def get_cpu_id(cpu_des):
    """Return an ID for a CPU based on their extended CPU
    string as returned via CPUID."""

    if not cpu_des:
        return "Unkown CPU ID"

    if 'intel' in cpu_des.lower():
        # Discard processor frequency
        tmp = cpu_des.split('@')[0]
        arr = tmp.split()
        return ' '.join(arr).replace('(R)', '')
    elif 'amd' in cpu_des.lower():
        return cpu_des.replace('(tm)', '')


def wait_for_hosts(session, timeout=600):
    """Wait until both hosts are up and live."""

    log.debug("Wait for hosts to come back online...")
    hosts = session.xenapi.host.get_all()
    num_hosts = len(hosts)
    log.debug("Total in %d hosts are being checked." % num_hosts)

    start = time.time()
    while not should_timeout(start, timeout):
        for host in hosts:
            rec = session.xenapi.host.get_record(host)
            hostname = session.xenapi.host.get_hostname(host)
            hostuuid = session.xenapi.host.get_uuid(host)
            if rec['enabled'] and \
                    session.xenapi.host_metrics.get_live(rec['metrics']):
                pif = get_management_interface(session, host)
                dev = session.xenapi.PIF.get_device(pif)
                try:
                    dom0 = _find_control_domain(session, host)
                    _get_control_domain_ip(session, dom0, dev)
                except:
                    log.debug("Host %s(%s) is up but not live yet." %
                              (hostname, hostuuid))
                    break
                else:
                    log.debug("Host %s(%s) is up and live." %
                              (hostname, hostuuid))
            else:
                log.debug("Host %s(%s) is not fully up yet." %
                          (hostname, hostuuid))
                break
        else:
            return
        time.sleep(2)

    raise Exception("Hosts(%s) failed to come back online" % hosts)


def get_ack_version(session, host=None):
    """Return the version string corresponding to the cert kit on a particular host"""
    try:
        return call_ack_plugin(session, 'get_ack_version', {}, host=host)
    except XenAPI.Failure as e:
        log.debug(
            "Failed to execute ack plugin call means ACK is not installed. Exception: %s" % str(e))
        return None


def combine_recs(rec1, rec2):
    """Utility function for combining two records into one."""
    rec = dict(rec1)
    for k, v in rec2.items():
        if k in rec.keys():
            raise Exception(
                "Cannot combine these recs, and keys overalp (%s)" % k)
        rec[k] = v

    return rec


def check_vm_ping_response(session, vm_ref, mip, count=3, timeout=300):
    """Function to run a simple check that a VM responds to a ping from the XenServer"""
    # Get VM IP and start timeout
    start = time.time()

    # Loop while waiting for an ICMP response
    while not should_timeout(start, timeout):

        call = ["ping", mip, "-c %s" % count]

        # Make the local shell call
        log.debug("Checking for ping response from VM %s at %s" % (
            vm_ref, mip))
        process = subprocess.Popen(call, stdout=subprocess.PIPE)    # NOSONAR
        stdout, stderr = process.communicate()
        response = str(stdout).strip()

        # Check for no packet loss. Note the space before '0%', this is
        # required.
        if " 0% packet loss" in response:
            log.debug("Ping response received from %s" % mip)
            return response

        log.debug("No ping response")
        time.sleep(3)

    raise Exception("VM %s IP %s could not be reached in the given timeout" % (
        vm_ref, mip))


def valid_ping_response(ping_response, max_loss=0):

    if max_loss > 100:
        raise Exception("Error: cannot have a loss of > 100%!")

    regex = re.compile(r"(?P<loss>\d+)\% packet loss")
    match = regex.search(ping_response)
    if match:
        # We've matched the regex for the ping result, now we
        # check whether the number of packets lost is acceptable.
        loss = int(match.group('loss'))
        return loss <= max_loss
    else:
        # We did not match the ping output, therefore we cannot
        # validate the response.
        return False


@log_exceptions
def get_dmidecode_output(session):
    """ Build dmidecode information data structure from output of dmidecode. """
    binfo = call_ack_plugin(session, 'get_dmidecode_output')
    buf = ''
    dmidecode_output = []
    for line in binfo.split(os.linesep):
        if len(line.strip()) == 0:
            dmidecode_output.append(buf)
            buf = ''
        else:
            buf += line + os.linesep
    return dmidecode_output


@log_exceptions
def search_dmidecode(session, keyword):
    """ Search ttype or busid from ds """
    ds = get_dmidecode_output(session)
    found = []
    for info in ds:
        if keyword in info:
            found.append(info)

    return found
