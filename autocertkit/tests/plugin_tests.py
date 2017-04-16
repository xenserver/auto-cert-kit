#!/usr/bin/python

import unittest
import os, os.path
import shutil
import sys 

from autocertkit import utils, ack_cli

utils.configure_logging('ack_tests')

class LogRotateTests(unittest.TestCase):
    """ Checking functionality and robust of netconf parser. """

    CLEANUP_LIST = []
    LOGFILES_LOC = ['/var/log/auto-cert-kit.log', '/var/log/auto-cert-kit-plugin.log']

    def setUp(self):
        if not os.path.exists('xcp'):
            os.mkdir('xcp')
        open('xcp' + os.path.sep + 'biosdevname.py', 'w').close()
        open('xcp' + os.path.sep + 'pci.py', 'w').close()
        open('xcp' + os.path.sep + '__init__.py', 'w').close()
        open('XenAPI.py', 'w').close()
        open('XenAPIPlugin.py', 'w').close()
        open('ssh.py', 'w').close()
        self.CLEANUP_LIST.append('XenAPI.py')
        self.CLEANUP_LIST.append('XenAPIPlugin.py')
        self.CLEANUP_LIST.append('ssh.py')
        self.CLEANUP_LIST.append('xcp')

    def tearDown(self):
        for filename in self.CLEANUP_LIST:
            if os.path.exists(filename):
                if os.path.isdir(filename):
                    shutil.rmtree(filename)
                else:
                    os.remove(filename)

    def _testLogRotate(self):
        shutil.copyfile('plugins/autocertkit', './plugin.py')
        import plugin
        plugin.LOGROTATE_CONF_LOC = './config/logrotate.conf'
        plugin.run_ack_logrotate(None, {})

    def testLogrotateConfFileExists(self):
        self._testLogRotate()
        self.assertTrue(os.path.exists('/etc/logrotate.d/autocertkit'))

    def testAreLogfilesCompressed(self):
        self._testLogRotate()
        for logfile in self.LOGFILES_LOC:
            self.assertTrue(os.path.exists(logfile + '.1.gz'))

    def testFileDoesNotStayUnlogrotated(self):
        self._testLogRotate()
        for logfile in self.LOGFILES_LOC:
           self.assertFalse(os.path.exists(logfile)) 

if __name__ == '__main__':
    unittest.main()       
