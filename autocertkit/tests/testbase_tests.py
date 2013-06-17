#!/usr/bin/python
import unittest

import unittest_base
from autocertkit import utils, test_generators, testbase
import sys

utils.configure_logging('ack_tests')

class TagsTests(unittest_base.DevTestCase):
    """Test that tags are enumerated correctly for a specified testclass"""

    def testCPUTestClassTags(self):
        cpuclass = testbase.CPUTestClass(self.session, self.config)
        tags = cpuclass.get_tags()
        assert 'CPU' in tags, "CPU tag not in the tags for CPUClass (%s)" % tags

    def testForTagMutilation(self):
        tg = test_generators.TestGenerator('fake_session', {}, 'nonexistent')
        for test_name, test_class in tg.get_test_classes():
            orig_tags = list(test_class('fake_session',{}).tags)
            new_tags = test_class('fake_session',{}).tags
            assert orig_tags == new_tags, "%s != %s - Tags are being mutilated. (%s)" % (orig_tags, new_tags, test_name)

if __name__ == '__main__':
    unittest.main()
