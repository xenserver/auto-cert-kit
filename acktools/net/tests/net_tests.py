import unittest
import re

from acktools.net import generate_mac

class MACGeneratorTest(unittest.TestCase):
    """Test util methods for manipulating MACs"""

    def _generate_mac(self):
        mac = generate_mac()
        mac_regex = r'([0-9A-Fa-f]{2}[:]){5}([0-9A-Fa-f]{2})'
        regex = re.compile(mac_regex)
        matches = regex.match(mac)
        if not matches:
            raise Exception("Error: did not generate valid MAC: '%s'" % mac)
        return mac

    def test_generate_mac(self):
        self._generate_mac()
