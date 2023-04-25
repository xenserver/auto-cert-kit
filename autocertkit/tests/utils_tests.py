#!/usr/bin/python3
import unittest
import tempfile
import os
import unittest_base
import sys
import shutil
import xenapi_mock
from config import CONFIG

from autocertkit import utils
from datetime import datetime

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


class IPv4AddrTests(unittest.TestCase):

    def test_check_ip_format(self):
        utils.IPv4Addr.check_ip_format('192.168.0.1')
        self.assertRaises(
            Exception, lambda: utils.IPv4Addr.check_ip_format('192.168.0.256'))
        self.assertRaises(
            Exception, lambda: utils.IPv4Addr.check_ip_format('192.168.1'))
        self.assertRaises(
            Exception, lambda: utils.IPv4Addr.check_ip_format('192.168.0.0.1'))
        self.assertRaises(
            Exception, lambda: utils.IPv4Addr.check_ip_format('192.168.0.01'))

    def test_check_netwrok_mask(self):
        utils.IPv4Addr.check_netwrok_mask('255.255.255.0')
        utils.IPv4Addr.check_netwrok_mask('255.255.0.0')
        utils.IPv4Addr.check_netwrok_mask('255.0.0.0')
        utils.IPv4Addr.check_netwrok_mask('255.255.240.0')
        self.assertRaises(
            Exception, lambda: utils.IPv4Addr.check_netwrok_mask('255.255.255.255'))
        self.assertRaises(
            Exception, lambda: utils.IPv4Addr.check_netwrok_mask('0.0.0.0'))

    def test_check_special_ip(self):
        utils.IPv4Addr.check_special_ip('192.168.0.1', '255.255.255.0')
        self.assertRaises(Exception, lambda: utils.IPv4Addr.check_special_ip(
            '192.168.0.0', '255.255.255.0'))
        self.assertRaises(Exception, lambda: utils.IPv4Addr.check_special_ip(
            '192.168.0.255', '255.255.255.0'))

    def test_split(self):
        subnet, host = utils.IPv4Addr.split('192.168.0.1', '255.255.255.0')
        self.assertEqual(subnet, (192 << 24) + (168 << 16) + (0 << 8))
        self.assertEqual(host, 1)

    def test_aton(self):
        n_ip = utils.IPv4Addr.aton('192.168.0.1')
        self.assertEqual(n_ip, (192 << 24) + (168 << 16) + (0 << 8) + 1)
        self.assertRaises(
            Exception, lambda: utils.IPv4Addr.aton('192.168.0.256'))

    def test_ntoa(self):
        ip = utils.IPv4Addr.ntoa((192 << 24) + (168 << 16) + (0 << 8) + 1)
        self.assertEqual(ip, '192.168.0.1')
        self.assertRaises(Exception, lambda: utils.IPv4Addr.ntoa(0x100000000))

    def test_validate_netmask(self):
        utils.IPv4Addr.validate_netmask('255.255.255.0')

    def test_validate_ip(self):
        utils.IPv4Addr.validate_ip('192.168.255.1', '255.255.255.0')

    def test_in_same_subnet(self):
        utils.IPv4Addr.in_same_subnet(
            '192.168.255.1', '192.168.255.254', '255.255.255.0')

    def test_validate(self):
        ip = utils.IPv4Addr('192.168.0.10', '255.255.255.0', '192.168.0.1')
        ip.validate()
        ip = utils.IPv4Addr('192.16.254.10', '255.240.0.0', '192.16.0.1')
        ip.validate()

    def test_get_subnet_host(self):
        ip = utils.IPv4Addr('192.168.0.2', '255.255.255.0', '192.168.0.1')
        subnet, host = ip.get_subnet_host()
        self.assertEqual(subnet, (192 << 24) + (168 << 16) + (0 << 8))
        self.assertEqual(host, 2)


class StaticIPManagerTests(unittest.TestCase):

    def setUp(self):
        self.conf = {'ip_start': '192.168.0.2',
                     'ip_end': '192.168.0.5',
                     'netmask': '255.255.255.0',
                     'gw': '192.168.0.1'}
        self.sm = utils.StaticIPManager(self.conf)

    def tearDown(self):
        self.sm.release_all()

    def test_get_ip(self):
        ip = self.sm.get_ip()
        self.assertEqual(ip.addr, '192.168.0.2')
        self.assertEqual(ip.netmask, '255.255.255.0')
        self.assertEqual(ip.gateway, '192.168.0.1')
        ip = self.sm.get_ip()
        self.assertEqual(ip.addr, '192.168.0.3')
        ip = self.sm.get_ip()
        self.assertEqual(ip.addr, '192.168.0.4')
        ip = self.sm.get_ip()
        self.assertEqual(ip.addr, '192.168.0.5')
        self.assertRaises(Exception, lambda: self.sm.get_ip())

        self.sm.release_all()

    def test_return_ip(self):
        free1 = self.sm.available_ips()
        ip = self.sm.get_ip()
        free2 = self.sm.available_ips()
        self.assertEqual(free1 - 1, free2)

        self.sm.return_ip(ip)
        free3 = self.sm.available_ips()
        self.assertEqual(free1, free3)

        self.assertRaises(Exception, lambda: self.sm.return_ip(ip))

        self.sm.release_all()


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


class NetworkLibMethodsTests(unittest.TestCase):
    """
    Host related functions unit tests.
    """

    def setUp(self):
        self.session = xenapi_mock.Session()

    def test_device_linkstate(self):
        utils.set_nic_device_status(self.session, 'eth0', 'down')
        utils.set_nic_device_status(self.session, 'eth1', 'up')
        self.assertRaises(Exception, lambda: utils.set_nic_device_status(
            self.session, 'invalidEth', 'up'))


class SimpleMethodsTests(unittest.TestCase):
    """
    Simple methods in utils module test
    """

    def setUp(self):
        self.session = xenapi_mock.Session()

    def test_kis_64_bit(self):
        self.assertTrue(utils.is_64_bit("x86_64"))
        self.assertFalse(utils.is_64_bit("i386"))
        self.assertFalse(utils.is_64_bit("i686"))

    def test_logging_methods(self):
        utils.init_ack_logging(self.session)

    def test_get_xenserver_version(self):
        self.session.hosts[0].xs_software_version = {
            'product_version': '7.0.93'}
        self.assertEqual(utils.get_xenserver_version(self.session), "7.0.93")

    def test_get_xcp_version(self):
        self.session.hosts[0].xs_software_version = {
            'platform_version': '2.1.4'}
        self.assertEqual(utils.get_xcp_version(self.session), "2.1.4")

    def test_get_ack_version(self):
        self.assertEqual(utils.get_ack_version(self.session), "1.2.3")
        self.assertEqual(utils.get_ack_version(
            self.session, self.session.hosts[1].opaque), "1.2.3")

        self.session.hosts[1].setAckVersion(None)
        self.assertEqual(utils.get_ack_version(
            self.session, self.session.hosts[0].opaque), "1.2.3")
        self.assertEqual(utils.get_ack_version(
            self.session, self.session.hosts[1].opaque), None)

        self.session.fail_plugin = True
        self.assertEqual(utils.get_ack_version(self.session), None)

    def test_get_system_info(self):
        self.session.hosts[0].dmidecode = ""
        self.assertDictEqual(utils.get_system_info(self.session), {})
        self.session.hosts[0].dmidecode = CONFIG["host"]["dmidecode"][0]
        self.assertDictEqual(utils.get_system_info(self.session), CONFIG[
                             "expected"]["get_system_info"][0])


if __name__ == '__main__':
    unittest.main()
