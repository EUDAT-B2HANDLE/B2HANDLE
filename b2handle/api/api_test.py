import unittest
import api

class B2Handle_test(unittest.TestCase):

    def setUp(self):
        self.b2handle = api.B2Handle()

    def tearDown(self):
        pass

    def dummy_test(self):
        dummy = self.b2handle.dummy()
        self.assertTrue(dummy)