#!/usr/bin/python
import unittest

import sys

sys.path.append('../kit/')
from utils import value_in_range, wrapped_value_in_range

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


if __name__ == '__main__':
    unittest.main()
