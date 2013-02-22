#!/usr/bin/python


import unittest
import sys
sys.path.append("../kit/")

import utils

class DevTestCase(unittest.TestCase):
    """Subclass unittest for extended setup/tear down
    functionality"""
    CONFIG_FILE = "config.txt"

    @classmethod
    def setUpClass(cls):
        #Read user config from file
        fh = open(cls.CONFIG_FILE,'r')
        cfg = {}
        for line in fh.readlines():
            arr = line.split(',')
            cfg[arr[0]] = arr[1].strip()
        cls.config = cfg
        print cls.config
        cls.session = utils.get_remote_xapi_session(cls.config)

    @classmethod
    def tearDownClass(cls):
        #Destroy the session
        cls.session.xenapi.session.logout(cls.session.handle)
        
