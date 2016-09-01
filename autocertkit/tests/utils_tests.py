#!/usr/bin/python
import unittest
import tempfile
import os
import unittest_base
import sys
import shutil
import xenapi_mock

from autocertkit import utils
from datetime import datetime

utils.configure_logging('ack_tests')

K = 1024
M = K * 1024
G = M * 1024


class ExpressionMatchingTests(unittest_base.DevTestCase):
    """Tests for checking that the expr_eval function
    works appropriately with XenServer version numbers"""

    def _exp_true(self, expr, val):
        res = utils.eval_expr(expr, val)
        self.assertEqual(res, True, "Expected %s %s to be True!" % (val, expr))

    def _exp_false(self, expr, val):
        res = utils.eval_expr(expr, val)
        self.assertEqual(
            res, False, "Expected %s %s to be False!" % (val, expr))

    def testGreaterThanTrue(self):
        self._exp_true('> 5.6', '6.0.0')
        self._exp_true('> 5.6', '5.6 FP1')
        self._exp_true('> 5.6 FP1', '5.6 SP2')
        self._exp_true('> 5.6 SP2', '6.0.0')

    def testGreaterThanFalse(self):
        self._exp_false('> 6.0.0', '5.6 SP2')
        self._exp_false('> 6.0.0', '5.6 FP1')
        self._exp_false('> 6.0.0', '5.6')
        self._exp_false('> 5.6 SP2', '5.6 FP1')


class StaticIPUtilsTests(unittest_base.DevTestCase):
    """Verify that the class methods for manipulating
    static IP addresses work correctly"""

    def _test_on_subnet(self, ip_a, ip_b, mask, expect=True):
        ipa = utils.IPv4Addr(ip_a, mask, '192.168.0.1')
        ipb = utils.IPv4Addr(ip_b, mask, '192.168.0.1')

        if ipa.on_subnet(ipb) and not expect:
            raise Exception("'%s' and '%s' on subnet '%s' - '%s'" % (ip_a,
                                                                     ip_b,
                                                                     mask,
                                                                     expect))

    def _test_increment_ip(self, start, result, expect=True):
        conf = {'ip_start': '192.168.0.1',
                'ip_end': '192.168.0.10',
                'netmask': '255.255.255.0',
                'gw': '192.168.0.1'}
        sim = utils.StaticIPManager(conf)

        res = sim.increment_ip_string(start)

        if res != result and expect:
            raise Exception("Error: '%s' incremeneted, should equal '%s' not '%s'" %
                            (start, result, res))

    def testOnSubnet(self):
        self._test_on_subnet('192.168.0.10',
                             '192.168.0.40',
                             '255.255.255.0')

    def testNotOnSubnet(self):
        self._test_on_subnet('192.168.0.10',
                             '192.128.0.40',
                             '255.255.255.0',
                             expect=False)

    def testIncrementIPs(self):
        self._test_increment_ip('192.168.0.1', '192.168.0.2')
        self._test_increment_ip('192.168.0.1', '192.168.0.10', expect=False)

    def testEnumerateIPs(self):
        conf = {'ip_start': '10.80.227.143',
                'ip_end': '10.80.227.151',
                'netmask': '255.255.0.0',
                'gw': '10.80.227.1'}

        full_list = ['10.80.227.143', '10.80.227.144', '10.80.227.145', '10.80.227.146',
                     '10.80.227.147', '10.80.227.148', '10.80.227.149', '10.80.227.150',
                     '10.80.227.151']

        sim = utils.StaticIPManager(conf)
        free_list = sim.ip_pool

        if len(free_list) != len(full_list):
            raise Exception("Error: we expect there to be %d IPs, enumerate produced %d." %
                            (len(full_list), len(free_list)))

        for i in range(len(full_list)):
            if free_list[i].addr != full_list[i]:
                raise Exception("Error: Enumerate IP returns %s, we expect %s" % (free_list,
                                                                                  full_list))

    def testLoanStaticIP(self):
        conf = {'ip_start': '192.168.0.5',
                'ip_end': '192.168.0.10',
                'netmask': '255.255.255.0',
                'gw': '192.168.0.1'}

        sim = utils.StaticIPManager(conf)

        borrowed_ip = sim.get_ip()
        assert(sim.available_ips() == 5)
        assert(len(sim.in_use) == 1)

        sim.return_ip(borrowed_ip)

        assert(sim.available_ips() == 6)
        assert(len(sim.in_use) == 0)


class ValueInRangeFunctions(unittest.TestCase):

    def test_simple(self):
        # Assert True
        self.assertTrue(utils.value_in_range(5 * G, 4 * G, 8 * G))
        self.assertTrue(utils.value_in_range(3 * G, 0, 4 * G))
        self.assertTrue(utils.value_in_range(4 * G, 0, 4 * G))
        self.assertTrue(utils.value_in_range(3 * G, 3 * G, 4 * G))

        # Assert False
        self.assertFalse(utils.value_in_range(4, 5, 500))
        self.assertFalse(utils.value_in_range(4 * G + 1, 0, 4 * G))
        self.assertFalse(utils.value_in_range(-1, 0, 4 * G))

    def test_wrap(self):
        self.assertTrue(utils.wrapped_value_in_range(8, 5, 15, 10))
        self.assertTrue(utils.wrapped_value_in_range(5 * K, 3 * G, 5 * G))
        self.assertTrue(utils.wrapped_value_in_range(3 * G, 2 * G, 4 * G))
        self.assertFalse(utils.wrapped_value_in_range(1 * G, 2 * G, 4 * G))
        self.assertFalse(utils.wrapped_value_in_range(2 * G, 3 * G, 5 * G))

        self.assertTrue(utils.wrapped_value_in_range(3965952210,
                                                     8248029658,
                                                     9067544228))


class ValidatePingResponses(unittest.TestCase):

    def test_valid_ping_responses(self):
        response = "20 packets transmitted, 19 received, 5% packet loss, time 19008ms"
        self.assertTrue(utils.valid_ping_response(response, max_loss=20))

    def test_invalid_ping_responses(self):
        response = "20 packets transmitted, 19 received, 5% packet loss, time 19008ms"
        self.assertFalse(utils.valid_ping_response(response, max_loss=0))

    def test_valid_equal_ping_responses(self):
        response = "20 packets transmitted, 19 received, 5% packet loss, time 19008ms"
        self.assertTrue(utils.valid_ping_response(response, max_loss=5))


class RebootFlagTimestamps(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        if os.path.exists(self.tmpdir):
            shutil.rmtree(self.tmpdir)

    def test_set_flag(self):
        flag = "%s/test_set_flag" % self.tmpdir
        utils.set_reboot_flag(flag_loc=flag)
        self.assertTrue(os.path.exists(flag))

    def test_read_flag(self):
        flag = "%s/test_read_flag" % self.tmpdir
        ts = datetime.now()
        utils.set_reboot_flag(flag_loc=flag)
        fts = utils.get_reboot_flag_timestamp(flag)
        fmt_str = "%Y-%m-%d %H:%M:%S"
        self.assertEqual(fts.strftime(fmt_str), ts.strftime(fmt_str))


class HostLibMethodsTests(unittest.TestCase):
    """
    Host related functions unit tests.
    """

    def setUp(self):
        self.session = xenapi_mock.Session()
        self.__enable_all_hosts()

    def __enable_all_hosts(self):
        for host in self.session.hosts:
            host.enabled = True
            host.metrics.live = True

    def test_wait_for_hosts(self):
        utils.wait_for_hosts(self.session)

        self.session.hosts[0].enabled = False
        self.assertRaises(Exception,
                          lambda: utils.wait_for_hosts(self.session, timeout=1))

        self.session.hosts[0].enabled = True
        self.session.hosts[1].metrics.live = False
        self.assertRaises(Exception,
                          lambda: utils.wait_for_hosts(self.session, timeout=1))

        self.__enable_all_hosts()


class PoolLibMethodsTests(unittest.TestCase):
    """
    Pool related functions unit tests.
    """

    def setUp(self):
        self.session = xenapi_mock.Session()

    def test_get_pool_master(self):
        self.assertTrue(utils.get_pool_master(self.session) ==
                        self.session.hosts[0].opaque)

    def test_get_pool_slaves(self):
        self.assertTrue(utils.get_pool_slaves(self.session) ==
                        [host.opaque for host in self.session.hosts[1:]])


class SimpleMethodsTests(unittest.TestCase):
    """
    Simple methods in utils module test
    """

    def test_kis_64_bit(self):
        self.assertTrue(utils.is_64_bit("x86_64"))
        self.assertFalse(utils.is_64_bit("i386"))
        self.assertFalse(utils.is_64_bit("i686"))


if __name__ == '__main__':
    unittest.main()
