#!/usr/bin/python

import unittest
import sys
import os
import os.path
import random
import exceptions
import tempfile
import shutil

from autocertkit import utils, ack_cli


class NetworkConfRobustTests(unittest.TestCase):
    """ Checking functionality and robust of netconf parser. """

    TMP_DIR = None
    PREFIX = "sameple_netconf_"
    POSTFIX = ".ini"
    CLEANUP_LIST = []

    default_vf_driver_name = "igbvf"
    default_vf_driver_pkg = "igbvf-2.3.9.6-1.x86_64.rpm"

    def _create_netconf_file(self, content):
        fullpath = self.TMP_DIR + os.sep + self.PREFIX + \
            str(random.random()) + self.POSTFIX

        fh = file(fullpath, "w")
        fh.write(content)
        fh.close()

        self.CLEANUP_LIST.append(fullpath)

        return fullpath

    def setUp(self):
        if not self.TMP_DIR or not os.path.exists(self.TMP_DIR):
            self.TMP_DIR = tempfile.mkdtemp()

    def tearDown(self):
        for filename in self.CLEANUP_LIST:
            if os.path.exists(filename):
                os.remove(filename)

        if os.path.exists(self.TMP_DIR):
            shutil.rmtree(self.TMP_DIR)

    def _runTest(self, content, output=None, exception=None):
        filename = self._create_netconf_file(content)
        if exception:
            self.assertRaises(exception, ack_cli.parse_netconf_file, filename)
        else:
            self.assertTrue(ack_cli.parse_netconf_file(filename) == output)

    def testExampleNetconf(self):
        output = {'eth0': {'network_id': 0, 'vlan_ids': [200, 204, 240],
                           'vf_driver_name': self.default_vf_driver_name, 'vf_driver_pkg': self.default_vf_driver_pkg},
                  'eth1': {'network_id': 1, 'vlan_ids': [200, 124],
                           'vf_driver_name': self.default_vf_driver_name, 'vf_driver_pkg': ''},
                  'eth2': {'network_id': 0, 'vlan_ids': [204, 240],
                           'vf_driver_name': '', 'vf_driver_pkg': self.default_vf_driver_pkg},
                  'eth3': {'network_id': 1, 'vlan_ids': [200],
                           'vf_driver_name': '', 'vf_driver_pkg': ''},
                  'static_0_200': {'gw': '192.168.0.1',
                                   'netmask': '255.255.255.0',
                                   'ip_end': '192.168.0.10',
                                   'ip_start': '192.168.0.2'},
                  'static_management': {'gw': '192.168.0.1',
                                        'netmask': '255.255.255.0',
                                        'ip_end': '192.168.0.10',
                                        'ip_start': '192.168.0.2'}
                  }

        self.assertTrue(ack_cli.parse_netconf_file(
            "autocertkit/networkconf.example") == output)

    def testSimple2Nic(self):
        content = """
[eth0]
network_id = 0
vlan_ids = 0
[eth1]
network_id = 0
vlan_ids = 0
"""
        output = {'eth0': {'network_id': 0, 'vlan_ids': [0],
                           'vf_driver_name': '', 'vf_driver_pkg': ''},
                  'eth1': {'network_id': 0, 'vlan_ids': [0],
                           'vf_driver_name': '', 'vf_driver_pkg': ''},
                  }
        self._runTest(content, output)

    def testWhiteSpace(self):
        content = """  
[eth0]
network_id =    0  
vlan_ids =      0  
vf_driver_name =    %s  
vf_driver_pkg =     %s  
[eth1]
network_id =    0  
vlan_ids =      0  
vf_driver_name =  
vf_driver_pkg =   
""" % (self.default_vf_driver_name, self.default_vf_driver_pkg)
        output = {'eth0': {'network_id': 0, 'vlan_ids': [0],
                           'vf_driver_name': self.default_vf_driver_name, 'vf_driver_pkg': self.default_vf_driver_pkg},
                  'eth1': {'network_id': 0, 'vlan_ids': [0],
                           'vf_driver_name': '', 'vf_driver_pkg': ''},
                  }
        self._runTest(content, output)

    def testEmptyLinesAndComments(self):
        content = """
# This is a sample text
[eth0]
network_id = 0  
vlan_ids = 0  
# comment following proper line.
vf_driver_name = %s
vf_driver_pkg = %s  
[eth1]
network_id = 0  
vlan_ids = 0
# comment following proper line.
vf_driver_name = %s

# comment starting with #
""" % (self.default_vf_driver_name, self.default_vf_driver_pkg, self.default_vf_driver_name)
        output = {'eth0': {'network_id': 0, 'vlan_ids': [0],
                           'vf_driver_name': self.default_vf_driver_name, 'vf_driver_pkg': self.default_vf_driver_pkg},
                  'eth1': {'network_id': 0, 'vlan_ids': [0],
                           'vf_driver_name': self.default_vf_driver_name, 'vf_driver_pkg': ''},
                  }
        self._runTest(content, output)

    def testStaticIP(self):
        content = """
[eth0]
network_id = 0
vlan_ids = 0
[eth1]
network_id = 0
vlan_ids = 0

[static_0_0]
ip_start = 192.168.0.2
ip_end = 192.168.0.10
netmask = 255.255.255.0
gw = 192.168.0.1
"""
        output = {'static_0_0': {'gw': '192.168.0.1',
                                 'netmask': '255.255.255.0',
                                 'ip_end': '192.168.0.10',
                                 'ip_start': '192.168.0.2'},
                  'eth0': {'network_id': 0, 'vlan_ids': [0],
                           'vf_driver_name': '', 'vf_driver_pkg': ''},
                  'eth1': {'network_id': 0, 'vlan_ids': [0],
                           'vf_driver_name': '', 'vf_driver_pkg': ''},
                  }
        self._runTest(content, output)

    def testStaticIPWrong(self):
        content = """
[eth0]
network_id = 0
vlan_ids = 0
[eth1]
network_id = 0
vlan_ids = 0

[static_0_0]
ip_start = 192.168.0.2
ip_end = 
netmask = 255.255.255.0
gw = 192.168.0.1
"""
        self._runTest(content, exception=Exception)

    def testStaticIPWrong2(self):
        content = """
[eth0]
network_id = 0
vlan_ids = 0
[eth1]
network_id = 0
vlan_ids = 0

[static_0_]
ip_start = 192.168.0.2
ip_end = 192.168.0.10
netmask = 255.255.255.0
gw = 192.168.0.1
"""
        self._runTest(content, exception=Exception)

    def testStaticIPWrong3(self):
        content = """
[eth0]
network_id = 0
vlan_ids = 0
[eth1]
network_id = 0
vlan_ids = 0

[static_0]
ip_start = 192.168.0.2
ip_end = 192.168.0.10
netmask = 255.255.255.0
gw = 192.168.0.1
"""
        self._runTest(content, exception=Exception)

    def testManagementStaticIP(self):
        content = """
[eth0]
network_id = 0
vlan_ids = 0
[eth1]
network_id = 0
vlan_ids = 0

[static_management]
ip_start = 192.168.0.2
ip_end = 192.168.0.10
netmask = 255.255.255.0
gw = 192.168.0.1
"""
        output = {'static_management': {'gw': '192.168.0.1',
                                        'netmask': '255.255.255.0',
                                        'ip_end': '192.168.0.10',
                                        'ip_start': '192.168.0.2'},
                  'eth0': {'network_id': 0, 'vlan_ids': [0],
                           'vf_driver_name': '', 'vf_driver_pkg': ''},
                  'eth1': {'network_id': 0, 'vlan_ids': [0],
                           'vf_driver_name': '', 'vf_driver_pkg': ''},
                  }

        self._runTest(content, output)

    def testSpaceBetweenValue(self):
        content = """
[eth0]
network_id = 0
vlan_ids = 100,2 00
[eth1]
network_id = 0
vlan_ids = 100
"""
        self._runTest(content, exception=Exception)

    def testWrongFormat1(self):
        content = """
[eth0]
network_id == 0
vlan_ids = 100,200
[eth1]
network_id = 0
vlan_ids = 100
"""
        self._runTest(content, exception=Exception)

    def testWrongFormat2(self):
        content = """
[eth0]
network_id = 0
vlan_ids = 100,200
[eth1]
network_id = 0
vlan_ids = 100;200
"""
        self._runTest(content, exception=Exception)

    def testWrongFormat3(self):
        content = """
[eth0]
network_id = 0
vlan_ids = 4097
[eth1]
network_id = 0
"""
        self._runTest(content, exception=Exception)

    def testWrongFormat4(self):
        content = """
[eth0]
network_id = 0x
[eth1]
network_id = 0
"""
        self._runTest(content, exception=Exception)

    def testWrongFormat4(self):
        content = """
[eth0]
network_id = 0
vlan_ids = 100x,200
[eth1]
network_id = 0
"""
        self._runTest(content, exception=Exception)

    def testUnknownSection(self):
        content = """
[eth0]
network_id = 0
[eth1]
network_id = 0
[x]
"""
        self._runTest(content, exception=Exception)


if __name__ == '__main__':
    unittest.main()
