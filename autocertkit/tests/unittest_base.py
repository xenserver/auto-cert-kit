#!/usr/bin/python3


import unittest
import sys

import autocertkit.utils


class DevTestCase(unittest.TestCase):
    """Subclass unittest for extended setup/tear down
    functionality"""

    session = "nonexistent"
    config = {}

    @classmethod
    def setUpClass(cls):
        # Read user config from file
        pass

    @classmethod
    def tearDownClass(cls):
        # Destroy the session
        pass
