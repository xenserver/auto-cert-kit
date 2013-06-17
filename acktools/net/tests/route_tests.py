#!/usr/bin/env python

import unittest
import mock

from acktools import utils
from acktools.net import route


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

class RouteMethodTests(unittest.TestCase):

    route_table = \
"""Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
0.0.0.0         10.80.2.1       0.0.0.0         UG    0      0        0 eth0
10.80.2.0       0.0.0.0         255.255.254.0   U     1      0        0 eth0
169.254.0.0     0.0.0.0         255.255.0.0     U     1000   0        0 eth0"""

    def test_get_all_routes(self):
        route.get_route_table = mock.Mock(return_value=self.route_table)
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


if __name__ == "__main__":
    unittest.main()
