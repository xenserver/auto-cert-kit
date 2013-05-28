#!/usr/bin/python
import unittest

import sys

sys.path.append('../kit/')
from utils import value_in_range, wrapped_value_in_range, valid_ping_response

K = 1024
M = K * 1024
G = M * 1024

class ValueInRangeFunctions(unittest.TestCase):
    
    def test_simple(self):
        #Assert True
        self.assertTrue(value_in_range(5*G, 4*G, 8*G))
        self.assertTrue(value_in_range(3*G, 0, 4*G))
        self.assertTrue(value_in_range(4*G, 0, 4*G))
        self.assertTrue(value_in_range(3*G, 3*G, 4*G))

        #Assert False
        self.assertFalse(value_in_range(4, 5, 500))
        self.assertFalse(value_in_range(4*G+1,0, 4*G))
        self.assertFalse(value_in_range(-1,0, 4*G))

    def test_wrap(self):
        self.assertTrue(wrapped_value_in_range(8, 5, 15, 10))
        self.assertTrue(wrapped_value_in_range(5*K, 3*G, 5*G))
        self.assertTrue(wrapped_value_in_range(3*G, 2*G, 4*G))
        self.assertFalse(wrapped_value_in_range(1*G, 2*G, 4*G))
        self.assertFalse(wrapped_value_in_range(2*G, 3*G, 5*G))

        self.assertTrue(wrapped_value_in_range(3965952210,
                                               8248029658,
                                               9067544228))


class ValidatePingResponses(unittest.TestCase):

    def test_valid_ping_responses(self):
        response = "20 packets transmitted, 19 received, 5% packet loss, time 19008ms"
        self.assertTrue(valid_ping_response(response, max_loss=20))

    def test_invalid_ping_responses(self):
        response = "20 packets transmitted, 19 received, 5% packet loss, time 19008ms"
        self.assertFalse(valid_ping_response(response, max_loss=0))

    def test_valid_equal_ping_responses(self):
        response = "20 packets transmitted, 19 received, 5% packet loss, time 19008ms"
        self.assertTrue(valid_ping_response(response, max_loss=5))

if __name__ == '__main__':
    unittest.main()
