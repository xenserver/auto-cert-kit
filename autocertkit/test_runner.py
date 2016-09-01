# Copyright (c) Citrix Systems Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms,
# with or without modification, are permitted provided
# that the following conditions are met:
#
# *   Redistributions of source code must retain the above
#     copyright notice, this list of conditions and the
#     following disclaimer.
# *   Redistributions in binary form must reproduce the above
#     copyright notice, this list of conditions and the
#     following disclaimer in the documentation and/or other
#     materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
# CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

"""Interface for running a test set. For CLI, you
should use auto_cert_kit.py. This is a non-public
interface for executing test cases whilst retaining
state.

A test file, dictating the full specified test names
to be executed, along with a config file containing
global parameters as set on the CLI should be passed
to this file.

The CLI, when it creates the test file, will add a init
script to run this python file on the test and config 
files on every boot. As we process the test file, we will
mark off each executed test. This gives us the ability to
perform a host reboot for particular tests, and then to
continue execution.

Each test will write its result out to a specified output
file, which at the end of the test file execution, will be
compiled into a report."""

import sys
import inspect
import network_tests
import cpu_tests
import storage_tests
import operations_tests
import testbase
import test_report
import time
import models

from utils import *

from xml.dom import minidom
from optparse import OptionParser


def parse_test_line(test_line):
    """Parse test line"""
    arr = test_line.split(',')
    if len(arr) < 2:
        raise Exception("Invalid test file. Only (%d) values" % len(arr))
    rec = {}
    rec['fqtn'] = arr[0]
    if arr[1].strip() == "yes":
        rec['executed'] = True
    else:
        rec['executed'] = False

    return rec


def parse_config_file(config_file):
    fh = open(config_file, 'r')
    lines = fh.readlines()
    rec = {}
    for line in lines:
        if not line.startswith('#'):
            arr = line.split('=')
            if len(arr) > 1:
                rec[arr[0].strip()] = arr[1].strip()
    fh.close()
    return rec


def mark_test_as_executed(test_file, test_name):
    mlist = []
    fh = open(test_file, 'r')
    lines = fh.readlines()
    fh.close

    for line in lines:
        mlist.append(parse_test_line(line))

    # Note, if execution crashes, we will have wipped
    # the test file.
    fh = open(test_file, 'w')
    for test_line in mlist:
        if test_line['fqtn'] == test_name:
            test_line['executed'] = True

        # Translate to text
        if test_line['executed']:
            executed = 'yes'
        else:
            executed = 'no'

        fh.write("%s,%s\n" % (test_line['fqtn'],
                              executed))


def is_test_class(node, name):
    conf = get_xml_attributes(node)
    return conf['name'] == name


def remove_child_nodes(parent_node):
    while parent_node.hasChildNodes():
        for node in parent_node.childNodes:
            parent_node.removeChild(node)
            node.unlink()


def update_xml_with_result(dom, class_node, results):
    """Update an xml config file object with results returned by a class test"""
    log.debug("Result Record: %s" % results)

    # Unlink the previous child nodes
    remove_child_nodes(class_node)

    for result in results:
        test_class, test_name = result['test_name'].split('.')

        method_node = dom.createElement('test_method')
        method_node.setAttribute('name', test_name)
        class_node.appendChild(method_node)

        def recurse_add_records_to_node(topnode, record):
            for k, v in record.iteritems():
                node = dom.createElement(k)
                topnode.appendChild(node)

                if type(v) == dict:
                    # Set attributes for element
                    for key, value in v.iteritems():
                        log.debug("Value = %s Type=%s" %
                                  (str(value), str(type(value))))
                        if type(value) == dict:
                            subnode = dom.createElement(key)
                            node.appendChild(subnode)
                            recurse_add_records_to_node(subnode, value)
                        elif type(value) == str:
                            node.setAttribute(str(key), str(value))
                elif type(v) == str or type(v) == int:
                    node.appendChild(dom.createTextNode(v))
                else:
                    log.warning("Casting node value to string %s who's type is %s" % (
                        str(v), str(type(v))))
                    node.appendChild(dom.createTextNode(str(v)))

        recurse_add_records_to_node(method_node, result)


@log_exceptions
def run_tests_from_file(test_file):
    """Open the testfile, retrieve the next un-executed to completion test"""

    session = get_local_xapi_session()

    # Ensure that all hosts in the pool have booted up. (for the case where
    # we have had to reboot to switch backend).
    wait_for_hosts(session)

    ack_model = models.parse_xml(test_file)

    config = ack_model.get_global_config()

    log.debug("ACK Model: %s" % ack_model.is_finished())
    if not ack_model.is_finished():
        # Ensure that we cleanup before running tests, in case
        # the system has been left in a failed state.
        pool_wide_cleanup(session)

    while not ack_model.is_finished():
        log.debug("Test Run Status: P %d, F %d, S %d, W %d" %
                  (ack_model.get_status()))

        tc_info = get_reboot_flag()
        test_name = None
        if tc_info and 'test_method' in tc_info:
            test_name = tc_info['test_method']

        next_test_class = ack_model.get_next_test_class(tc_info)
        next_test_method = next_test_class.get_next_test_method(test_name)
        if not next_test_method:
            raise Exception("No more test method to run from test class: %s" %
                            next_test_class.get_name())

        # Merge device specific config into the global config dict object
        # that will then be passed to the test class.
        config['device_config'] = next_test_class.get_device_config()

        log.debug("About to run test: '%s'" % (next_test_class.get_name()))
        test_inst = get_test_class(next_test_class.get_name())(session, config)
        result = test_inst.run(
            to_bool(get_value(config, 'debug')), next_test_method.get_name())

        # Update the python objects with results
        next_test_class.update(result)

        # Save the updated test class back to the config file
        next_test_class.save(test_file)

        # Reset reboot flag
        clear_reboot_flag()

    log.debug("Logging out of xapi session %s" % session.handle)
    session.xenapi.session.local_logout()

    # Note: due to XAPI character restrictions, we have to encode this filename
    # in the XAPI plugin itself. This should be fixed in the future if
    # possible.

    txt_result_file = "/root/results.txt"
    result = test_report.post_test_report(test_file, txt_result_file)

    # Note: due to the XAPI character restrictions, we can not
    # pass to the plugin paths. This means that the test_run.conf file
    # has to be hardcoded as part of the output package in the plugin.
    package_loc = call_ack_plugin(session, 'create_output_package')

    if result:
        log.debug("Your hardware has passed all of the expected tests")
        log.debug("Please upload %s to a Citrix Tracker submission." %
                  package_loc)
    else:
        log.debug("Error: Not all of the hardware tests passed certification.")
        log.debug("Please look at the logs found in /var/log/auto-cert-kit.log")
        log.debug("A fuller summary of the tests can be found in %s" %
                  txt_result_file)
        log.debug("The output package has been saved here: %s" % package_loc)

    return test_file, package_loc


def get_test_class(fqtn):
    arr = fqtn.split('.')
    if len(arr) not in [2, 3]:
        raise Exception(
            "Test name specified is incorrect. It should be module.class or module.submodule.class")

    test_class_module = ".".join(arr[:-1])
    test_class_name = arr[-1]

    modules = get_module_names(test_class_module)
    assert len(modules) == 1

    test_classes = inspect.getmembers(sys.modules[modules[0]],
                                      inspect.isclass)

    for test_name, test_class in test_classes:
        if test_class_name == test_name:
            return test_class

    raise Exception("Specified FQTN not found! (%s)" % fqtn)


if __name__ == "__main__":
    # Main function entry point
    global log

    log = configure_logging('auto-cert-kit')

    parser = OptionParser(usage="%prog [-c] [-t]", version="%prog 0.1")

    parser.add_option("-t", "--test file",
                      dest="testfile",
                      help="Specify the test sequence file")

    (options, _) = parser.parse_args()

    if not options.testfile:
        raise Exception("Error, please pass the correct arguments")

    log.debug("test_runner about to run from test_file %s" % options.testfile)

    test_file, output = run_tests_from_file(options.testfile)
