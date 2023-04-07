#!/usr/bin/python3
import unittest

import unittest_base
import sys
from autocertkit import test_generators, testbase, utils


def expect_system_exit(func, code='0'):
    try:
        func()
    except SystemExit as exp:
        if str(exp) == code:
            # Valid System Exit
            pass
        else:
            raise exp


class DocumentationTests(unittest_base.DevTestCase):
    """Test that documentation is correctly generated for the testkit"""

    def testPrintTestList(self):
        expect_system_exit(test_generators.print_all_test_classes)

    def testPrintClassInformation(self):
        for test_class_name, test_class in test_generators.enumerate_all_test_classes():
            expect_system_exit(
                lambda: test_generators.print_documentation(test_class_name))

    def testClassDescrition(self):
        """Make sure that each test class has a defined docstring outlining
        the purpose of the test."""
        classes_without_docstrings = []
        for test_class_name, test_class in test_generators.enumerate_all_test_classes():
            if test_class.__doc__.strip() == "":
                classes_without_docstrings.append(test_class_name)

        if classes_without_docstrings:
            raise Exception("These classes have no docstrings: %s" %
                            classes_without_docstrings)


if __name__ == '__main__':
    unittest.main()
