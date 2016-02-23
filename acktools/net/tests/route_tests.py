#!/usr/bin/env python

import unittest
import mock

from acktools import utils
from acktools.net import route
import acktools


class RouteObjectTests(unittest.TestCase):

    route_rec = {
                 'dest': '0.0.0.0',
                 'gw': '10.80.2.1',
                 'mask': '0.0.0.0',
                 'iface': 'eth1',
                }

    def setUp(self):
        self.route_obj = route.Route(**self.route_rec)

    def test_get_dest(self):
        self.assertEqual(self.route_obj.get_dest(),
                         self.route_rec['dest'])

    def test_get_gw(self):
        self.assertEqual(self.route_obj.get_gw(),
                         self.route_rec['gw'])

    def test_get_mask(self):
        self.assertEqual(self.route_obj.get_mask(),
                         self.route_rec['mask'])

    def test_get_iface(self):
        self.assertEqual(self.route_obj.get_iface(),
                         self.route_rec['iface'])

    def test_get_record(self):
        rec = self.route_obj.get_record()

        def validate_key(key):
            self.assertEqual(rec[key], self.route_rec[key])

        for key in self.route_rec.keys():
            validate_key(key)


class RouteTableTests(unittest.TestCase):

    route_recs = [
                   {'dest': '0.0.0.0', 'gw': '10.80.2.1',
                    'mask': '0.0.0.0', 'iface': 'eth1'},
                   {'dest': '192.168.0.0', 'gw':'192.168.0.1',
                    'mask': '255.255.255.0', 'iface':'eth3'}
                 ]

    def setUp(self):
        route_list = []
        for rec in self.route_recs:
            route_obj = route.Route(**rec)
            route_list.append(route_obj)

        self.route_table = route.RouteTable(route_list)

    def test_get_routes(self):
        routes = self.route_table.get_routes()
        self.assertEqual(len(routes), 2)

    def test_get_routes_non_matching_gw(self):
        routes = self.route_table.get_routes(dest='192.168.0.0',
                                             mask='255.255.255.0',
                                             gw='192.168.0.2',
                                             iface='eth3')
        self.assertEqual(routes, [])

    def test_get_routes_non_matching_iface(self):
        routes = self.route_table.get_routes(dest='192.168.0.0',
                                             mask='255.255.255.0',
                                             gw='192.168.0.1',
                                             iface='eth1')
        self.assertEqual(routes, [])

    def test_get_route(self):
        for rec in self.route_recs:
            routes = self.route_table.get_routes(rec['dest'], rec['mask'])
            self.assertEqual(len(routes), 1)
            route = routes.pop()
            self.assertNotEqual(route, None)
            self.assertEqual(route.get_iface(), rec['iface'])
            self.assertEqual(route.get_gw(), rec['gw'])

    def test_get_nonexistent_route(self):
        routes = self.route_table.get_routes('192.145.2.5','255.255.255.0')
        self.assertEqual(routes, [])
        routes = self.route_table.get_routes('192.168.0.0','255.255.254.0')
        self.assertEqual(routes, [])

    def test_get_missing_routes(self):
        route_obj = route.Route(**self.route_recs[0])
        rt = route.RouteTable([route_obj])
        missing = self.route_table.get_missing(rt)
        self.assertEqual(len(missing), 1)

    def test_get_no_missing_routes(self):
        missing = self.route_table.get_missing(self.route_table)
        self.assertEqual(missing, [])


ROUTE_TABLE = \
"""Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
0.0.0.0         10.80.2.1       0.0.0.0         UG    0      0        0 eth0
10.80.2.0       0.0.0.0         255.255.254.0   U     1      0        0 eth0
169.254.0.0     0.0.0.0         255.255.0.0     U     1000   0        0 eth0"""

class RouteMethodTests(unittest.TestCase):

    @mock.patch('acktools.net.route.get_route_table', mock.Mock(return_value=ROUTE_TABLE))
    def test_get_all_routes(self):
        routes = route.get_all_routes()

        self.assertEqual(len(routes), 3)

        def assert_about_obj(route_obj, gw, mask, iface):
            self.assertEqual(route_obj.get_gw(), gw)
            self.assertEqual(route_obj.get_mask(), mask)
            self.assertEqual(route_obj.get_iface(), iface)

        for route_obj in routes:
            if route_obj.get_dest() == '0.0.0.0':
                assert_about_obj(route_obj, '10.80.2.1', '0.0.0.0', 'eth0')
            elif route_obj.get_dest() == '10.80.2.0':
                assert_about_obj(route_obj, '0.0.0.0', '255.255.254.0', 'eth0')
            elif route_obj.get_dest() == '169.254.0.0':
                assert_about_obj(route_obj, '0.0.0.0', '255.255.0.0', 'eth0')
            else:
                raise Exception("Error: route not in original list! " \
                                "'%s'" % route)

    @mock.patch('acktools.net.route.get_route_table', mock.Mock(return_value='Blah'))
    def test_invalid_routing_table(self):
        self.assertRaises(Exception, route.get_all_routes)


if __name__ == "__main__":
    unittest.main()

