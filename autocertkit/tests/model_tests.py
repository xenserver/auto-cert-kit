#!/usr/bin/python3

import unittest
import unittest_base
from autocertkit import utils, test_generators, models
from xml.dom import minidom


class StreamMock(object):
    """Fake stream to get result."""

    def __init__(self):
        self.__data = ""

    def write(self, data):
        self.__data += data

    def output(self):
        return self.__data


class ReportPrintsTests(unittest_base.DevTestCase):
    """Test Report output is generated properly"""

    device = {'vendor': 'fakevender',
              'PCI_id': 'fakeid',
              'PCI_subsystem': 'fakess',
              'device': 'fakedevice',
              'driver': 'fake',
              'PCI_description': 'fakedesc',
              'modelname': 'fake AMD model',
              'product_version': 'fakeversion',
              'build_number': 'fakebuildnumber'
              }
    config = {'exclude': ['LSTOR', 'OVS', 'BRIDGE', 'OPS', 'CPU']}

    def createDeviceNode(self, generator):
        tg = generator(self.session, self.config, self.device)
        doc = minidom.Document()
        device_node = doc.createElement('device')
        device_node.setAttribute('udid', str(tg.get_uid()))
        device_node.setAttribute('tag', tg.TAG)
        for k, v in self.device.items():
            device_node.setAttribute(k, v)
        cts_node = doc.createElement('certification_tests')
        device_node.appendChild(cts_node)

        return device_node

    def testLSReport(self):
        device_node = self.createDeviceNode(
            test_generators.StorageTestGenerator)
        report = StreamMock()
        models.Device(device_node).print_report(report)

        assert 'fakevender:fakedevice' in report.output(
        ), "Failed to compile vender and device."
        expected = "Storage device using the fake driver"
        assert expected in report.output(), "Failed to compile driver."
        assert 'fakedesc' in report.output(), "Failed to compile PCI_description."

    def testNetReport(self):
        device_node = self.createDeviceNode(
            test_generators.NetworkAdapterTestGenerator)
        report = StreamMock()
        models.Device(device_node).print_report(report)

        assert 'fakeid' in report.output(), "Failed to compile PCI_id."
        assert 'fakedesc' in report.output(), "Failed to compile PCI_description."
        assert 'fakess' in report.output(), "Failed to compile PCI_subsystem."

    def testCPUReport(self):
        device_node = self.createDeviceNode(
            test_generators.ProcessorTestGenerator)
        report = StreamMock()
        models.Device(device_node).print_report(report)

        assert 'fake AMD model' in report.output(), "Failed to compile model name"

    def testOpsReport(self):
        device_node = self.createDeviceNode(
            test_generators.OperationsTestGenerator)
        report = StreamMock()
        models.Device(device_node).print_report(report)

        assert 'fakeversion' in report.output(), "Failed to compile version."
        assert 'fakebuildnumber' in report.output(), "Failed to compile build number."


if __name__ == '__main__':
    unittest.main()
