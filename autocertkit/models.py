# Copyright (c) 2005-2022 Citrix Systems Inc.
# Copyright (c) 2023 Cloud Software Group, Inc.
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

"""Module for providing python object models for the XML config/test files"""

from xml.dom import minidom
from utils import *

import operator


def get_attributes(xml_node):
    """ When given an XML node, return a dictionary object
    with all of the key/values as specified in the XML"""
    rec = {}
    if not xml_node.hasAttributes():
        return rec

    for i in range(0, xml_node.attributes.length):
        attr_node = xml_node.attributes.item(i)
        rec[attr_node.name] = attr_node.value

    return rec


def get_child_elems(xml_node):
    return [node for node in xml_node.childNodes
            if node.nodeType == node.ELEMENT_NODE]


def remove_child_nodes(parent_node):
    while parent_node.hasChildNodes():
        for node in parent_node.childNodes:
            parent_node.removeChild(node)
            node.unlink()


class Element(object):
    name = None
    val = None
    attr = {}

    def __init__(self, name, value=None, attributes=None):
        self.name = name
        if value:
            self.set_value(value)
        if attributes:
            self.set_attributes(attributes)

    def get_name(self):
        return self.name

    def set_value(self, value):
        self.val = value

    def set_attributes(self, value):
        self.attr = value

    def create_xml_node(self, dom):
        """Create the xml node representation of this object"""
        xml_node = dom.createElement(str(self.get_name()))

        # Set the elements XML attributes
        for k, v in self.attr.items():
            xml_node.setAttribute(str(k), str(v))

        # Set the elements value
        if self.val:
            txt_node = dom.createTextNode(str(self.val))
            xml_node.appendChild(txt_node)

        return xml_node


class XMLNode(Element):

    def __init__(self, node):
        self.name = node.tagName
        self.attr = get_attributes(node)
        if not node.childNodes:
            # No child nodes
            self.val = None
        else:
            assert(len(node.childNodes) == 1)
            self.val = node.childNodes[0].data


class DeviceTestClassMethod(object):
    """Model for a test class method, housed inside of a
    particular test class"""
    elems = []
    attr = {}

    def __init__(self, parent, testmethod_node):
        self.parent = parent
        self.attr = get_attributes(testmethod_node)
        self.name = "%s.%s" % (self.parent.name, self.attr['name'])
        elem_list = []
        for node in get_child_elems(testmethod_node):
            elem_list.append(XMLNode(node))
        self.elems = elem_list

    def _match_key(self, key, text):
        for elem in self.elems:
            if elem.name == key:
                return elem.val == text
        # If we can't find a result, then default value
        # is assumed to be False.
        return False

    def _get_key(self, key):
        for elem in self.elems:
            if elem.name == key:
                return elem.val
        return None

    def get_name(self):
        return self.name

    def get_control(self):
        return self._get_key('control')

    def has_passed(self):
        """ This method has passed. """
        return self._match_key('result', 'pass')

    def has_failed(self):
        """ This method has failed. """
        return self._match_key('result', 'fail')

    def has_skipped(self):
        """ This method has not run. """
        return self._match_key('result', 'skip')

    def is_waiting(self):
        """ This method has not been executed yet. """
        return self._match_key('status', 'init')

    def is_running(self):
        """ This method is still running. """
        return self._match_key('status', 'running')
    
    def is_rerun_waiting(self):
        """ This method is waiting to rerun. """
        return self._match_key('rerun_status', 'init')
    
    def is_rerun_started(self):
        """ This method is started to rerun. """
        return self._match_key('rerun_status', 'start')
    
    def is_rerun_passed(self):
        """ This method is passed by rerun. """
        return self._match_key('rerun_status', 'passed')
    
    def is_rerun_failed(self):
        """ This method is failed again. """
        return self._match_key('rerun_status', 'failed')

    def is_done(self):
        """ This method has done. """
        return self._match_key('status', 'done')

    def create_xml_node(self, dom):
        """Write this test method out to an xml node"""
        xml_node = dom.createElement('test_method')
        for k, v in self.attr.items():
            xml_node.setAttribute(str(k), str(v))

        for elem in self.elems:
            node = elem.create_xml_node(dom)
            xml_node.appendChild(node)

        return xml_node

    def update_elem(self, k, v):
        for elem in self.elems:
            if elem.get_name() == k:

                if type(v) is dict:
                    elem.set_attributes(v)
                else:
                    elem.set_value(v)
                return

        # Element does not already exist, so create it.

        if type(v) is dict:
            new_el = Element(k, None, v)
        else:
            new_el = Element(k, v, None)

        # Ensure we don't update all of the element classes
        elem_list = list(self.elems)
        elem_list.append(new_el)
        self.elems = elem_list

    def update(self, rec):
        """Update elements in this method object from a provided record"""
        for k, v in rec.items():
            self.update_elem(k, v)


class DeviceTestClass(object):
    """Model for a test class"""
    test_methods = []
    config = {}

    def __init__(self, parent, testclass_node):
        self.parent = parent
        self.config = get_attributes(testclass_node)
        self.name = self.config['name']
        method_list = []
        for method_node in get_child_elems(testclass_node):
            method_list.append(DeviceTestClassMethod(self, method_node))
        self.test_methods = method_list

    def get_caps(self):
        """ Return a list of caps supported by this
        device based on the tests that have passed/failed """
        return eval(self.config['caps'])    # NOSONAR

    def get_order(self):
        """Return the integer number specified by the test class to indicate
        when it should be scheduled relative to other tests. Note, that if test
        classes bear the same integer order, there is no strict ordering between
        them"""
        return self.config['order']

    def has_passed(self):
        for method in self.get_methods():
            if not method.has_passed() and self.is_required():
                return False
        # Otherwise, we have passed all required
        # Tests.
        return True

    def get_name(self):
        return self.name

    def get_methods(self):
        return self.test_methods

    def get_methods_to_run(self):
        return sorted([method for method in self.test_methods if method.is_waiting()],
                      key=lambda a: a.get_name())

    def get_method_by_name(self, name):
        """Note, the method name is unique"""
        for method in self.get_methods():
            if name in method.get_name():
                return method
        return None

    def get_next_test_method(self, test_name=None):
        """Picks next testing method."""
        test_methods = self.get_methods_to_run()
        # If test_name is given, pick it.
        if test_name:
            for method in test_methods:
                if test_name in method.get_name():
                    return method
            raise Exception("test_name %s is given, but cannot find it from waiting method list of test class %s"
                            % (test_name, self.get_name()))

        if not test_methods:
            return None

        return test_methods[0]

    def get_device_config(self):
        """Return the device specific config record"""
        return self.parent.config

    def is_required(self):
        return REQ_CAP in self.get_caps()

    def is_finished(self):
        for test_method in self.test_methods:
            if test_method.is_waiting():
                return False
        return True

    def group_test_method_by_status(self):
        """Group test method by status"""
        done, waiting, running = ([], [], [])
        for test_method in self.test_methods:
            if test_method.is_done():
                done.append(test_method)
            elif test_method.is_waiting():
                waiting.append(test_method)
            elif test_method.is_running():
                running.append(test_method)
            else:
                raise Exception(
                    "Unknown status of test method %s", test_method.get_name())

        return done, waiting, running

    def update(self, results):
        """Take the output of a test run (list of records), and update the results
        of the test methods held within this test class"""
        for result in results:
            method = self.get_method_by_name(result['test_name'])
            if not method:
                raise Exception("Error: the method '%s' doesn't belong to the TestClass '%s'" %
                                (result['test_name'], self.get_name()))
            method.update(result)

    def save(self, filename):
        """Save the information in this test class to the specified test file.
        It is assumed that we are mostly updating this file, and so matching nodes are overwritten
        with the results as stored in this object"""

        dom = minidom.parse(filename)
        dev_nodes = dom.getElementsByTagName('device')

        # Retrieve the udid for each matching device
        for dev_node in dev_nodes:
            if dev_node.getAttribute('udid') == str(self.parent.udid):
                tc_nodes = dev_node.getElementsByTagName('test_class')

        # Check that at least one node was returned
        if not tc_nodes:
            raise Exception("Could not find the test class '%s' for device '%d' in filename '%s'" %
                            (self.get_name(), self.parent.udid, filename))

        # Find the node belonging to this test class by matching name
        node_list = [node for node in tc_nodes if node.getAttribute(
            'name') == self.get_name()]

        # Check for the existence of *only one* node
        if len(node_list) != 1:
            raise Exception(
                "Error: Expecting there not to be test class duplicates. '%s'" % node_list)
        # Take the only node
        class_node = node_list.pop()

        # Remove all child nodes (methods) - nothing in the test class
        # node is updated.
        remove_child_nodes(class_node)

        # Re-create new child method nodes
        for method in self.get_methods():
            node = method.create_xml_node(dom)
            class_node.appendChild(node)

        fh = open(filename, 'w')
        fh.write(dom.toxml())
        fh.close()

        return "OK"


class Device(object):
    """Model for a device object that would be added to HCL"""
    udid = None
    config = None
    test_classes = []

    def __init__(self, xml_device_node):
        """ Initialise the test class, taking an XML node
        and converting into this model"""
        self.config = get_attributes(xml_device_node)
        self.tag = self.config['tag']
        self.udid = self.config['udid']  # Unique device id

        # We only care about child element nodes
        child_elems = [node for node in xml_device_node.childNodes
                       if node.nodeType == node.ELEMENT_NODE]

        # We expect there to be one child node 'certification_tests'
        if len(child_elems) != 1:
            raise Exception(
                "Error: unexpected XML format. Should only be one child node: %s" % child_elems)

        xml_cert_tests_node = child_elems[0]

        test_class_list = []
        for test_node in get_child_elems(xml_cert_tests_node):
            test_class_list.append(DeviceTestClass(self, test_node))
        self.test_classes = test_class_list

    def get_test_methods(self, filter_required=None):
        """Return a list of test methods"""
        res = []
        for test_class in self.test_classes:
            if test_class.is_required() == filter_required:
                continue
            for test_method in test_class.get_methods():
                res.append(test_method)
        return res

    def get_id(self):
        """Depending on type, return the appropriate ID for this
        device"""
        try:
            if self.tag == "NA":
                return self.config['PCI_id']
            if self.tag == "CPU":
                return get_cpu_id(self.config['modelname'])
            if self.tag == "LS":
                pci_id = self.config['vendor'] + ":" + self.config["device"]
                return pci_id
            if self.tag == "OP":
                xs_id = "XenServer %s" % self.config['product_version']
                return xs_id
        except Exception as e:
            log.error("Exception occurred getting ID: '%s'" % str(e))
        return "Unknown ID"

    def get_subsystem(self):
        """Return the information of PCI subsysem if it exists."""
        if (self.tag == "NA" or self.tag == "LS") and "PCI_subsystem" in self.config:
            return self.config["PCI_subsystem"]
        return ""

    def get_description(self):
        """Depending on the type, return the appropriate description
        for this device"""
        try:
            if self.tag == "NA":
                return self.config['PCI_description']
            if self.tag == "CPU":
                return self.config['modelname']
            if self.tag == "LS":
                ls_info = "Storage device using the %s driver" % self.config[
                    'driver']
                if 'PCI_description' in self.config:
                    ls_info += "\n\t%s" % self.config['PCI_description']
                return ls_info
            if self.tag == "OP":
                build_id = "build %s" % self.config['build_number']
                return build_id
        except Exception as e:
            log.error("Exception occurred getting Description: '%s'" % str(e))
        return "Unknown Device"

    def get_caps(self):
        """ Return the rec of capabilities this hardware
        device supports. For example, a NIC might be able to 
        be supported on the HCL, but may not support GRO. Other
        devices however may well do."""
        caps = {}

        for test_class in self.test_classes:
            tcaps = test_class.get_caps()
            supported = test_class.has_passed()

            if supported:
                for cap in tcaps:
                    if not cap in caps.keys():
                        # Only update, if not in rec. Since it's
                        # supported by this case, if a previous result
                        # has set the cap to false, we should not override
                        # that.
                        caps[cap] = True
            else:
                # Not supported case
                for cap in tcaps:
                    caps[cap] = False

        return caps

    def get_test_classes_to_run(self):
        """Return a list of test classes which have not yet been executed to completion."""
        tcs_to_run = []
        for test_class in self.test_classes:
            if not test_class.is_finished():
                tcs_to_run.append(test_class)
        return tcs_to_run
    
    def get_failed_test_methods(self):
        """Return a list of test methods which were failed."""
        tm_failed = []
        for test_class in self.test_classes:
            for test_method in test_class.get_methods():
                if test_method.has_failed():
                    tm = (test_class, test_method)
                    tm_failed.append(tm)
        return tm_failed
    
    def get_rerun_test_methods(self):
        """Return a list of test methods which have been rerun."""
        tm_rerun = []
        for test_class in self.test_classes:
            for test_method in test_class.get_methods():
                if test_method.is_rerun_started():
                    tm = (test_class, test_method)
                    tm_rerun.append(tm)
        return tm_rerun

    def group_test_classes_by_status(self):
        """"Group test classes by status"""
        done, waiting, running = ([], [], [])
        for test_class in self.test_classes:
            ds, ws, rs = test_class.group_test_method_by_status()
            if ds and not ws and not rs:
                # class in dones means its all methods done
                done.append(test_class)
            if ws:
                waiting.append(test_class)
            if rs:
                running.append(test_class)

        return done, waiting, running

    def has_passed(self):
        """Return a bool as to whether the device
        can be posted on the HCL."""

        # Look through the test classes for this device,
        # and if any of them have no passed (i.e. not passed
        # required
        for test_class in self.test_classes:
            if test_class.is_required() and not test_class.has_passed():
                return False
        return True

    def get_status(self):
        """Return number of tests that have passed, failed and are waiting to be
        executed"""

        tests_passed = [tm for tm in self.get_test_methods()
                        if tm.has_passed()]
        tests_failed = [tm for tm in self.get_test_methods()
                        if tm.has_failed()]
        tests_skipped = [tm for tm in self.get_test_methods()
                         if tm.has_skipped()]
        tests_waiting = [tm for tm in self.get_test_methods()
                         if tm.is_waiting()]
        tests_running = [tm for tm in self.get_test_methods()
                         if tm.is_running()]
        tests_rerun_waiting = [tm for tm in self.get_test_methods()
                         if tm.has_failed() and tm.is_rerun_waiting()]
        tests_rerun_passed = [tm for tm in self.get_test_methods()
                         if tm.is_rerun_passed()]
        tests_rerun_failed = [tm for tm in self.get_test_methods()
                         if tm.is_rerun_failed()]
        tests_rerun_started = [tm for tm in self.get_test_methods()
                         if tm.is_rerun_started()]


        return {'passed': len(tests_passed),
                'failed': len(tests_failed),
                'skipped': len(tests_skipped),
                'waiting': len(tests_waiting),
                'running': len(tests_running),
                'rerun_waiting': len(tests_rerun_waiting),
                'rerun_passed': len(tests_rerun_passed),
                'rerun_failed': len(tests_rerun_failed),
                'rerun_started': len(tests_rerun_started),
                }

    def print_report(self, stream):
        """Write a report for the device specified"""
        stream.write("\n")
        stream.write("Device ID: %s\n" % self.get_id())
        stream.write("Description: %s\n" % self.get_description())
        subsystem = self.get_subsystem()
        if subsystem and len(subsystem) > 0:
            subsystem = stream.write("%s\n" % subsystem)
        stream.write("#########################\n\n")

        tests_passed = [test_method for test_method in self.get_test_methods()
                        if test_method.has_passed()]
        tests_failed_req = [test_method for test_method in self.get_test_methods(False)
                            if test_method.has_failed()]
        tests_failed_noreq = [test_method for test_method in self.get_test_methods(True)
                              if test_method.has_failed()]
        tests_skipped_req = [test_method for test_method in self.get_test_methods(False)
                             if test_method.has_skipped()]
        tests_skipped_noreq = [test_method for test_method in self.get_test_methods(True)
                               if test_method.has_skipped()]
        tests_rerun_passed = [test_method for test_method in self.get_test_methods()
                        if test_method.is_rerun_passed()]
        tests_rerun_failed_req = [test_method for test_method in self.get_test_methods(False)
                            if test_method.is_rerun_failed()]

        if not self.has_passed():
            stream.write(
                "This device has not passed all the neccessary tests and so will not be supported.")
            stream.write(
                "In order for this device to be supported, this device must pass the following tests:\n")
            for method in tests_failed_req:
                stream.write("%s\n" % method.get_name())
            for method in tests_skipped_req:
                stream.write("%s\n" % method.get_name())
        else:
            stream.write("Capabilities:\n")
            for k, v in self.get_caps().items():
                if v:
                    reqval = "Supported"
                else:
                    reqval = "Unsupported"

                stream.write("%s: %s\n" % (k, reqval))

        self.print_results(stream, tests_passed, "Tests that passed:")
        self.print_results(stream, tests_failed_req, "Tests that failed:")
        self.print_results(stream, tests_failed_noreq,
                           "None required tests that failed:")
        self.print_results(stream, tests_skipped_req +
                           tests_skipped_noreq, "Tests that skipped:")
        
        # Rerun test results
        if tests_rerun_passed:
            self.print_results(stream, tests_rerun_passed, "Tests that passed by rerunning:")
        if tests_rerun_failed_req:
            self.print_results(stream, tests_rerun_failed_req, "Tests failed again in rerun:")

    def print_results(self, stream, res, header):
        if res:
            stream.write("\n" + header + "\n")
            for test in res:
                stream.write("%s\n" % test.name)


class AutoCertKitRun(object):
    """Python class for representing the XML config file as an object"""

    config = {}
    devices = []

    def __init__(self, xml_file):
        dom = minidom.parse(xml_file)

        gcns = dom.getElementsByTagName('global_config')
        # We only expect one global_config xml_node
        if len(gcns) != 1:
            log.debug("Found global_config nodes: %s" % gcns)
            raise Exception(
                "Unexpected XML file format. Found %d global_config nodes." % len(gcns))

        self.config = get_attributes(gcns[0])

        device_nodes = dom.getElementsByTagName('device')
        device_list = []
        for device_node_xml in device_nodes:
            device_list.append(Device(device_node_xml))
        self.devices = device_list

    def get_global_config(self):
        return self.config

    def get_status(self):
        """Return the number of tests across all devices that have passed, failed and
        are waiting to be executed."""
        passed = 0
        failed = 0
        skipped = 0
        waiting = 0
        running = 0
        rerun_waiting = 0
        rerun_passed = 0
        rerun_failed = 0
        rerun_started = 0
        for device in self.devices:
            status = device.get_status()
            passed = passed + status['passed']
            failed = failed + status['failed']
            skipped = skipped + status['skipped']
            waiting = waiting + status['waiting']
            running = running + status['running']
            rerun_waiting = rerun_waiting + status['rerun_waiting']
            rerun_passed = rerun_passed + status['rerun_passed']
            rerun_failed = rerun_failed + status['rerun_failed']
            rerun_started = rerun_started + status['rerun_started']
            
        return {'passed': passed,
                'failed': failed,
                'skipped': skipped,
                'waiting': waiting,
                'running': running,
                'rerun_waiting': rerun_waiting,
                'rerun_passed': rerun_passed,
                'rerun_failed': rerun_failed,
                'rerun_started': rerun_started
                }

    def is_rerunning(self):
        status = self.get_status()
        return status['rerun_started']
    
    def is_finished(self):
        """Return true if the test run has finished"""
        status = self.get_status()
        return not (status['waiting'] + status['running'])
    
    def need_rerun(self):
        """Return true if there are test failed and haven't done the rerun"""
        status = self.get_status()
        return status['rerun_waiting']

    def get_next_test_class(self, tc_info=None):
        """Return the next test class to run. This allows us
        to have some basic scheduling logic to group together
        tests that, for instance, use the same network backend
        so as to reduce the number of reboots required."""

        tcs_to_run = []

        # Iterate through devices
        for device in self.devices:
            if tc_info and 'device' in tc_info and device.udid != tc_info['device']:
                continue
            # Get the test class still to run
            tcs = device.get_test_classes_to_run()
            self.get_next_test_classes(tcs_to_run, tcs, tc_info)

        if not tcs_to_run:
            if tc_info:
                raise Exception(
                    "REBOOT_FLAG is set but cannot find matching test case.")
            return None

        # Sort the list according the the integer priorities
        # that each test class has been given.
        # 'Reverse' specified, inorder to '.pop()'.

        tcs_to_run.sort(key=operator.itemgetter(1), reverse=True)

        # Return the test class at the top of the list
        return tcs_to_run.pop()[0]

    def get_next_test_classes(self, tcs_to_run, tcs, tc_info):
        for tc in tcs:
            if tc_info and 'test_class' in tc_info and tc_info['test_class'] not in tc.get_name():
                continue
            if tc_info and 'test_method' in tc_info and not tc.get_method_by_name(tc_info['test_method']):
                continue

            # Append a tuple - (test_class, order)
            # Order index will be used below for sorting.
            tcs_to_run.append((tc, tc.get_order()))

    def get_next_test(self):
        """Get the next test class and method to run"""
        tcs_to_run = []

        for device in self.devices:
            dones, waitings, runnings = device.group_test_classes_by_status()
            if runnings:
                test_class = runnings.pop()
                _, _, running_methods = test_class.group_test_method_by_status()
                test_method = running_methods.pop()
                return test_class, test_method

            for tc in waitings:
                tcs_to_run.append((tc, tc.get_order()))

        tcs_to_run.sort(key=operator.itemgetter(1), reverse=True)

        test_class = tcs_to_run.pop()[0]
        _, waiting_methods, _ = test_class.group_test_method_by_status()
        test_method = waiting_methods.pop()
        return test_class, test_method


def create_models(xml_file):
    """Create the python object model from a given XML file"""

    dom = minidom.parse(xml_file)

    device_nodes = dom.getElementsByTagName('device')

    device_list = []

    for device_node_xml in device_nodes:
        device_list.append(Device(device_node_xml))
    return device_list


def parse_xml(xml_file):
    """Create the python model for a test_run xml file"""

    return AutoCertKitRun(xml_file)
