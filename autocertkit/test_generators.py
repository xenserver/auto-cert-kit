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

"""Python module for generating the list of tests specific to each device"""

import sys
import inspect
import utils
import os

import network_tests
import cpu_tests
import storage_tests
import operations_tests
import testbase
from xml.dom import minidom


class TestGenerator(object):
    """Test class for enumerating test config and information. The class
    will load all imported test classes, and filter based on tag, device, and
    other such information. This class can then be used by modules like test_runner
    to compose a list of tests that should be exectued per device.

    The class is also able to output the config into a desired format. Currently, 
    we make use of the append_xml_config method that outputs the test to be run,
    and the config that each test requires.
    """

    TAG = False
    uidlist = []

    def __init__(self, session, config, interface=None):
        self.session = session
        self.config = config
        self.interface = interface
        self.prereq_check()

    def prereq_check(self):
        """Function for ensuring that specific prereq conditions are checked and raised before
        execution."""
        pass

    def select_test_by_config(self, test_classes):
        """Select test classes to run by config"""
        if "run_classes" not in self.config.keys():
            return test_classes

        classes = self.config["run_classes"].split()
        ret = []
        for cla in classes:
            for i in test_classes:
                # i is tuple of ("class name", class obj)
                if cla == i[0]:
                    ret.append(i)
        return ret

    def filter_test_classes(self, test_classes):
        """optional filter method that could be used to remove particular tests from the
        normal set if required. List consists of (testname, testclass)"""
        return test_classes

    def get_test_classes(self):
        """Return a list of tuples (test_class_name, test_class) that should be run.
        This is based on the tag specified on class init"""

        test_classes_to_run = []
        for test_module in utils.get_module_names('_tests'):
            test_classes = inspect.getmembers(sys.modules[test_module],
                                              inspect.isclass)
            # utils.log.debug(test_classes)
            for test_name, test_class in test_classes:
                # Check that the class is subclassed from the base TestClass
                if issubclass(test_class, testbase.TestClass):
                    # If a tag exists, then we should make sure that the classes tags list
                    # contains the specified tag. If not, then we will add the test to be run
                    # anyway.
                    if self.TAG and (not self.TAG in test_class(self.session, self.config).tags):
                        continue
                    test_classes_to_run.append(
                        ("%s.%s" % (test_module, test_name), test_class))
        # Return the tuple (test_class_name, test_class) where the test_class
        # value is a class object
        return self.filter_test_classes(test_classes_to_run)

    def get_uid(self):
        """Return a unique number, as compared with other uses of this function.
        The counter allows us to assign a 'unique id' to each device being tested."""

        # In order to make sure we provide a unique value, we modify the base test classes list
        # relying on the semantics python provides. Each instantiation of this class inherits the
        # appended list, and so acts as a global variable. We can then populate the list, providing
        # a counting id for the caller.

        self.uidlist.append(len(self.uidlist))
        return len(self.uidlist)

    def get_device_config(self):
        """Retrieve info about interface from biosdevname"""
        if not self.interface:
            return {}
        devices = utils.get_master_network_devices(self.session)
        for device_rec in devices:
            if device_rec['Kernel_name'] == self.interface:
                return device_rec
        raise Exception("Specified interface %s appears not to exist on master" %
                        self.interface)

    def append_xml_config(self, doc, xml_node):
        """Append xml config for running the tests. xml_node should be the devices
        xml tag under which each device to be certified hangs."""
        device_node = doc.createElement('device')

        device_config = self.get_device_config()
        if device_config:
            for k, v in device_config.items():
                device_node.setAttribute(k, v)

        # Set the unique device id
        device_node.setAttribute('udid', str(self.get_uid()))

        # Set the device type
        device_node.setAttribute('tag', self.TAG)

        cts_node = doc.createElement('certification_tests')
        device_node.appendChild(cts_node)

        test_classes = self.get_test_classes()
        for test_class_name, test_class in test_classes:
            xcp_version = utils.get_xcp_version(self.session)
            skip_this = self.set_test_class_cap(test_class, xcp_version)

            class_node = doc.createElement('test_class')
            class_node.setAttribute('name', test_class_name)
            class_node.setAttribute('caps', str(
                test_class(self.session, self.config).caps))
            class_node.setAttribute('order', str(
                test_class(self.session, self.config).order))

            test_methods = test_class(self.session, self.config).list_tests()
            for method in test_methods:
                self.add_method_node(
                    doc, skip_this, test_class_name, xcp_version, class_node, method)

            cts_node.appendChild(class_node)

        xml_node.appendChild(device_node)

    def set_test_class_cap(self, test_class, xcp_version):
        if test_class.REQUIRED_FOR:
            if utils.eval_expr(test_class.REQUIRED_FOR, xcp_version):
                if not utils.REQ_CAP in test_class.caps:
                    test_class.caps.append(utils.REQ_CAP)
            else:
                if utils.REQ_CAP in test_class.caps:
                    test_class.caps.remove(utils.REQ_CAP)
                return True
        return False

    def add_method_node(self, doc, skipthis, test_class_name, xcp_version, class_node, method):
        method_node = doc.createElement('test_method')
        method_node.setAttribute('name', str(method))

        # Result/Info fields
        result_node = doc.createElement('result')
        info_node = doc.createElement('info')
        if skipthis:
            result_node.appendChild(doc.createTextNode('skip'))
            reason_node = doc.createElement('reason')
            reason_node.appendChild(doc.createTextNode('%s is not required for XCP %s.'
                                                       % (test_class_name, xcp_version)))
            method_node.appendChild(reason_node)
        else:
            result_node.appendChild(doc.createTextNode('NULL'))

        method_node.appendChild(result_node)
        method_node.appendChild(info_node)
        testname_node = doc.createElement('test_name')
        testname_node.appendChild(doc.createTextNode('%s.%s' %
                                                     (test_class_name.split('.')[1], str(method))))
        method_node.appendChild(testname_node)

        status_node = doc.createElement('status')
        if skipthis:
            status_node.appendChild(doc.createTextNode('done'))
        else:
            status_node.appendChild(doc.createTextNode('init'))
            
        rerun_node = doc.createElement('rerun_status')
        if skipthis:
            rerun_node.appendChild(doc.createTextNode('done'))
        else:
            rerun_node.appendChild(doc.createTextNode('init'))   
             
        control_node = doc.createElement('control')
        method_node.appendChild(status_node)
        method_node.appendChild(control_node)
        method_node.appendChild(rerun_node)

        class_node.appendChild(method_node)


class NetworkAdapterTestGenerator(TestGenerator):
    """TestGenerator class specific for NA tests"""
    TAG = 'NA'

    def prereq_check(self):
        if 'static' in self.config.keys():
            ip_manager = utils.StaticIPManager(self.config['static'])
            num_ips_provided = ip_manager.total_ips

            # Work out the maximum required number of IPs of tests
            # which are going to be run.
            min_ips_required = 0
            for test_name, test_class in self.get_test_classes():
                class_ips = test_class(
                    self.session, self.config).num_ips_required
                if class_ips > min_ips_required:
                    min_ips_required = class_ips

            if min_ips_required > num_ips_provided:
                raise Exception("For these tests, at least %d static IPs must be provided. You provided only %d" % (
                    min_ips_required, num_ips_provided))

    def filter_test_classes(self, test_classes):
        utils.log.debug("Config Keys: %s" % self.config.keys())
        # Handle the case where XenRT wants to not run the bonding test case
        # due to the fact the machines are not configured with two NICs

        if "run_classes" in self.config.keys():
            return self.select_test_by_config(test_classes)

        def append_filter(testname, dont_run):
            for item in dont_run:
                if item in testname:
                    return False
            return True

        if 'OVS' in self.config['exclude']:
            test_classes = [(testname, testclass) for testname, testclass
                            in test_classes if not testclass.network_backend or
                            testclass.network_backend == 'bridge']
        if 'BRIDGE' in self.config['exclude']:
            test_classes = [(testname, testclass) for testname, testclass
                            in test_classes if not testclass.network_backend or
                            testclass.network_backend == 'vswitch']

        if 'singlenic' in self.config.keys() and self.config['singlenic'] == "true":
            dont_run = ["BondingTestClass", "MTUPingTestClass"]
            return [(testname, testclass) for testname, testclass
                    in test_classes if append_filter(testname, dont_run)]
        else:
            return test_classes


class ProcessorTestGenerator(TestGenerator):
    """TestGenertor class specific to Processor tests"""
    TAG = 'CPU'

    def filter_test_classes(self, test_classes):
        if "run_classes" in self.config.keys():
            return self.select_test_by_config(test_classes)

        if 'CPU' in self.config['exclude']:
            return []
        return test_classes

    def get_device_config(self):
        """Retrieve host cpu info from the pool master"""
        rec = super(ProcessorTestGenerator, self).get_device_config()
        master_ref = utils.get_pool_master(self.session)
        cpu_rec = self.session.xenapi.host.get_cpu_info(master_ref)
        return utils.combine_recs(rec, cpu_rec)


class StorageTestGenerator(TestGenerator):
    """TestGenertor class specific to Storage tests"""
    TAG = 'LS'

    def __init__(self, session, config, device):
        super(StorageTestGenerator, self).__init__(session, config)
        self.device = device

    def filter_test_classes(self, test_classes):
        if "run_classes" in self.config.keys():
            return self.select_test_by_config(test_classes)

        if 'LSTOR' in self.config['exclude']:
            return []
        return test_classes

    def get_device_config(self):
        """Retrieve info regarding the local SCSI devices"""
        rec = super(StorageTestGenerator, self).get_device_config()
        return utils.combine_recs(rec, self.device)


class OperationsTestGenerator(TestGenerator):
    """TestGenertor class specific to Operations tests"""
    TAG = 'OP'

    def filter_test_classes(self, test_classes):
        if "run_classes" in self.config.keys():
            return self.select_test_by_config(test_classes)

        if 'OPS' in self.config['exclude']:
            return []
        if 'CRASH' in self.config['exclude']:
            test_classes = [(testname, testclass) for testname, testclass
                            in test_classes if 'CrashDump' not in testname]
        return test_classes

    def get_device_config(self):
        """Retrieve XenServer version info from the pool master"""
        rec = super(OperationsTestGenerator, self).get_device_config()
        rec = utils.combine_recs(rec, utils.get_xs_info(self.session))
        rec = utils.combine_recs(rec, utils.get_system_info(self.session))
        return rec

##############################################################################


class DeviceXMLGenerator(object):

    TAGS = []
    CLS = None

    def __init__(self, session, config, mode, network_ifs, storage_devs):
        self.session = session
        self.config = config
        self.mode = mode
        self.network_ifs = network_ifs
        self.storage_devs = storage_devs

    def should_generate(self):
        return self.mode in self.TAGS or self.mode == 'ALL'

    def append_xml_config(self, doc, devices_node):
        if self.should_generate():
            self._append_xml_config(doc, devices_node)

    def _append_xml_config(self, doc, devices_node):
        gen = self.CLS(self.session, self.config)
        gen.append_xml_config(doc, devices_node)


class NetworkAdaptersXMLGenerator(DeviceXMLGenerator):

    TAGS = ["NET"]

    def _append_xml_config(self, doc, devices_node):
        for iface in self.network_ifs:
            natg = NetworkAdapterTestGenerator(
                self.session, self.config, iface)
            natg.append_xml_config(doc, devices_node)


class StorageAdaptersXMLGenerator(DeviceXMLGenerator):

    TAGS = ["LSTOR"]

    def _append_xml_config(self, doc, devices_node):
        for dev in self.storage_devs:
            lstg = StorageTestGenerator(self.session, self.config, dev)
            lstg.append_xml_config(doc, devices_node)


class ProcessorsXMLGenerator(DeviceXMLGenerator):

    TAGS = ["CPU"]
    CLS = ProcessorTestGenerator


class OperationsXMLGenerator(DeviceXMLGenerator):

    TAGS = ["OPS"]
    CLS = OperationsTestGenerator


XML_GENERATORS = [
    NetworkAdaptersXMLGenerator,
    StorageAdaptersXMLGenerator,
    ProcessorsXMLGenerator,
    OperationsXMLGenerator,
]

##############################################################################


def print_documentation(object_name):
    print("--------- %s ---------" % utils.bold(object_name))
    print("")
    classes = enumerate_all_test_classes()
    for test_class_name, test_class in classes:
        arr = (object_name).split('.')
        if test_class_name == object_name:
            # get the class info
            print("%s: %s" % (utils.bold('Prereqs'),
                              test_class.required_config))
            print("%s: %s" % (utils.bold('Collects'), test_class.collects))
            print("")
            print(utils.format(test_class.__doc__))
            print("")
            print("%s:" % (utils.bold('Tests')))
            inst = test_class(None, {})
            for method in inst.list_tests():
                print(method)
            print("")
            sys.exit(0)
        elif len(arr) == 3 and ".".join(arr[:2]) == test_class_name:
            # get the method info
            print(utils.format(getattr(test_class, arr[2]).__doc__))
            print("")
            sys.exit(0)

    print("The test name specified (%s) was incorrect. Please specify the full test name." % object_name)
    sys.exit(0)


def enumerate_all_test_classes():
    tg = TestGenerator('nonexistent_session',
                       'nonexistent_config', 'nonexistent_iface')
    return tg.get_test_classes()


def print_all_test_classes():
    print("---------- %s ---------" % utils.bold("Test List"))
    classes = enumerate_all_test_classes()
    for test_class_name, test_class in classes:
        obj = test_class('nonexistent_session', {})
        for test_name in obj.list_tests():
            print("%s.%s" % (test_class_name, test_name))
    sys.exit(0)
