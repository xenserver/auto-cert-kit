#!/usr/bin/python
import unittest

import test_base
import sys

sys.path.append('../kit/')
import utils

utils.configure_logging('ack_tests')

class DroidVMTests(test_base.DevTestCase):
    """Test cases for utility functions creating droid vms"""

    def testPrepareReturnsReference(self):
        ref = utils.prepare_droid_vm(self.session, self.config)
        self.assertIsNotNone(ref, "Reference not returned by prepare_droid_vm")
        print self.session.xenapi.VM.get_name_label(ref)

    def testPrepareCreatesVM(self):
        vm_recs = self.session.xenapi.VM.get_all()
        droid_vms = utils.get_droid_templates(self.session)
        print "Droid vms %s" % droid_vms
        #Destroy all droid vms
        for vm in droid_vms:
            self.session.xenapi.VM.destroy(vm)
        droid_vms = utils.get_droid_templates(self.session)
        self.assertEqual(len(droid_vms),0,"Not all the droid templates have been removed!")
        ref = utils.prepare_droid_vm(self.session, self.config)
        droid_vms = utils.get_droid_templates(self.session)
        self.assertEqual(len(droid_vms),1,"The droid VM has not be created!")

    def testStaticDroidDeployment(self):
        network_ref = self.session.xenapi.network.get_all()[0]
        static_conf = {'ip_start': '192.168.0.2',
                       'ip_end': '192.168.0.9',
                       'netmask': '255.255.255.0',
                       'gw': '192.168.0.1'}
        vm1, vm2 = utils.deploy_two_droid_vms(self.session, network_ref, static_conf)



class ExpressionMatchingTests(test_base.DevTestCase):
    """Tests for checking that the expr_eval function
    works appropriately with XenServer version numbers"""

    def _exp_true(self, expr, val):
        res = utils.eval_expr(expr, val)
        self.assertEqual(res, True, "Expected %s %s to be True!" % (val, expr))

    def _exp_false(self, expr, val):
        res = utils.eval_expr(expr, val)
        self.assertEqual(res, False, "Expected %s %s to be False!" % (val, expr))

    def testGreaterThanTrue(self):
        self._exp_true('> 5.6', '6.0.0')
        self._exp_true('> 5.6', '5.6 FP1')
        self._exp_true('> 5.6 FP1', '5.6 SP2')
        self._exp_true('> 5.6 SP2', '6.0.0')
    
    def testGreaterThanFalse(self):
        self._exp_false('> 6.0.0', '5.6 SP2')
        self._exp_false('> 6.0.0', '5.6 FP1')
        self._exp_false('> 6.0.0', '5.6')
        self._exp_false('> 5.6 SP2', '5.6 FP1')
        

class StaticIPUtilsTests(test_base.DevTestCase):
    """Verify that the class methods for manipulating
    static IP addresses work correctly"""

    def _test_on_subnet(self, ip_a, ip_b, mask, expect=True):
        ipa = utils.IPv4Addr(ip_a, mask, '192.168.0.1')
        ipb = utils.IPv4Addr(ip_b, mask, '192.168.0.1')

        if ipa.on_subnet(ipb) and not expect:
            raise Exception("'%s' and '%s' on subnet '%s' - '%s'" % (ip_a,
                                                                     ip_b,
                                                                     mask,
                                                                     expect))
    def _test_increment_ip(self, start, result, expect=True):
        conf = {'ip_start':'192.168.0.1',
                'ip_end': '192.168.0.10',
                'netmask': '255.255.255.0',
                'gw': '192.168.0.1'}
        sim = utils.StaticIPManager(conf)

        res = sim.increment_ip_string(start)

        if res != result and expect:
            raise Exception("Error: '%s' incremeneted, should equal '%s' not '%s'" %
                            (start, result, res))

    def testOnSubnet(self):
        self._test_on_subnet('192.168.0.10',
                             '192.168.0.40',
                             '255.255.255.0')

    def testNotOnSubnet(self):
        self._test_on_subnet('192.168.0.10',
                             '192.128.0.40',
                             '255.255.255.0',
                             expect=False)
                          
    
    def testIncrementIPs(self):
        self._test_increment_ip('192.168.0.1','192.168.0.2')
        self._test_increment_ip('192.168.0.1','192.168.0.10', expect=False)

    def testEnumerateIPs(self):
        conf = {'ip_start':'10.80.227.143',
                'ip_end': '10.80.227.151',
                'netmask': '255.255.0.0',
                'gw': '10.80.227.1'}

        full_list = ['10.80.227.143', '10.80.227.144', '10.80.227.145', '10.80.227.146',
                     '10.80.227.147', '10.80.227.148', '10.80.227.149', '10.80.227.150',
                     '10.80.227.151']

        sim = utils.StaticIPManager(conf)
        free_list = sim.free

        if len(free_list) != len(full_list):
            raise Exception("Error: we expect there to be %d IPs, enumerate produced %d." % 
                            (len(full_list), len(free_list)))

        for i in range(len(full_list)):
            if free_list[i].addr != full_list[i]:
                raise Exception("Error: Enumerate IP returns %s, we expect %s" % (free_list,
                                                                              full_list))

    def testLoanStaticIP(self):
        conf = {'ip_start':'192.168.0.5',
                'ip_end': '192.168.0.10',
                'netmask': '255.255.255.0',
                'gw': '192.168.0.1'}

        sim = utils.StaticIPManager(conf)

        borrowed_ip = sim.get_ip()
        print "Borrowed %s" % borrowed_ip.addr

        print "Free: %d In Use: %d" % (len(sim.free), len(sim.in_use))
        assert(len(sim.free) == 5)
        assert(len(sim.in_use) == 1)
        
        sim.return_ip(borrowed_ip)

        assert(len(sim.free) == 6)
        assert(len(sim.in_use) == 0)

        
        

if __name__ == '__main__':
    unittest.main()
