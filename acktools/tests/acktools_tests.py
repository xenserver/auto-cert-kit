#!/usr/bin/env python

import unittest
import acktools
import subprocess
from mock import Mock


class MockProcess:

    def __init__(self, output, err=None):
        self.output = output
        self.returncode = 1 if err else 0
        self.__stderr = err

    def stderr(self):
        return self.__stderr

    def stdout(self):
        return self.output

    def communicate(self):
        return self.stdout(), self.stderr()


class MakeLocalCallTests(unittest.TestCase):

    def test_no_exceptions(self):
        call = ['ls', '/tmp/']
        acktools.make_local_call(call)

    def test_expect_exception(self):
        call = ['ls', '/tmp']
        real_popen = subprocess.Popen
        setattr(subprocess, 'Popen', lambda *args,
                **kwargs: MockProcess('No such file!', 'No such file!'))
        self.assertRaises(Exception, acktools.make_local_call, call)
        setattr(subprocess, 'Popen', real_popen)


if __name__ == "__main__":
    unittest.main()
