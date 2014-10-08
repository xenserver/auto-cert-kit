#!/usr/bin/python

import unittest
import sys
import os, os.path
import random
import exceptions
import tempfile
import shutil

from autocertkit import utils, ack_cli

utils.configure_logging('ack_tests')

class NetworkConfRobustTests(unittest.TestCase):
    """ Checking functionality and robust of netconf parser. """

    TMP_DIR = None
    PREFIX = "sameple_netconf_"
    CLEANUP_LIST = []


    def _create_netconf_file(self, content):
        fullpath = self.TMP_DIR + os.sep + self.PREFIX + str(random.random())

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

    def _runTest(self, content, output = None, exception = None):
        filename = self._create_netconf_file(content)
        if exception:
            self.assertRaises(exception, ack_cli.parse_netconf_file, filename)
        else:
            self.assertTrue(ack_cli.parse_netconf_file(filename) == output)
        
    def testExampleNetconf(self):
        output = {'static_0_200': {'gw': '192.168.0.1',
                                'netmask': '255.255.255.0',
                                'ip_end': '192.168.0.10',
                                'ip_start': '192.168.0.2'},
                'eth0': {'network_id': 0, 'vlan_ids': [200, 204, 240]},
                'eth1': {'network_id': 1, 'vlan_ids': [200, 124]},
                'eth2': {'network_id': 0, 'vlan_ids': [204, 240]},
                'eth3': {'network_id': 1, 'vlan_ids': [200]}
                }

        self.assertTrue(ack_cli.parse_netconf_file("autocertkit/networkconf.example") == output)


    def testSimple2Nic(self):
        content = """eth0 = 0,[0]
eth1 = 0,[0]
"""
        output = {'eth0': {'network_id': 0, 'vlan_ids': [0]},
                 'eth1': {'network_id': 0, 'vlan_ids': [0]},
                }
        self._runTest(content, output)

    def testWhiteSpace(self):
        content = """  eth0   =    0,  [ 0 ]
	eth1=0,[0]
"""
        output = {'eth0': {'network_id': 0, 'vlan_ids': [0]},
                 'eth1': {'network_id': 0, 'vlan_ids': [0]},
                }
        self._runTest(content, output)

    def testEmptyLinesAndComments(self):
        content = """
# This is a sample text
eth0 = 0, [0] # comment following proper line.

eth1 = 0, [0]


# comment starting with #
 # comment following space.
"""
        output = {'eth0': {'network_id': 0, 'vlan_ids': [0]},
                 'eth1': {'network_id': 0, 'vlan_ids': [0]},
                }
        self._runTest(content, output)

    def testStaticIP(self):
        content = """eth0   =    0,  [ 0 ]
eth1=0,[0]
static_0_0 = 192.168.0.2,192.168.0.10,255.255.255.0,192.168.0.1
"""
        output = {'static_0_0': {'gw': '192.168.0.1',
                                'netmask': '255.255.255.0',
                                'ip_end': '192.168.0.10',
                                'ip_start': '192.168.0.2'},
                 'eth0': {'network_id': 0, 'vlan_ids': [0]},
                 'eth1': {'network_id': 0, 'vlan_ids': [0]},
                }
        self._runTest(content, output)

    def testStaticIPWrong(self):
        content = """eth0 = 0,[0]
eth1 = 0,[0]
static_0_0 = 192.168.0.2,255.255.255.0,192.168.0.1

"""
        self._runTest(content, exception=Exception)

    def testStaticIPWrong2(self):
        content = """eth0 = 0,[0]
eth1 = 0,[0]
static_0_ = 192.168.0.2,192.168.0.10,255.255.255.0,192.168.0.1

"""
        self._runTest(content, exception=Exception)

    def testSpaceBetweenValue(self):
        content = """eth0 = 0,[100,2 00]
eth1 = 0,[100]
"""
        self._runTest(content, exception=Exception)

    def testWrongFormat1(self):
        content = """eth0 == 0,[100,200]
eth1 = 0,[100]
"""
        self._runTest(content, exception=Exception)

    def testWrongFormat2(self):
        content = """eth0 = 0,[100,200]
eth1 = 0
"""
        self._runTest(content, exception=Exception)

if __name__ == '__main__':
    unittest.main()

