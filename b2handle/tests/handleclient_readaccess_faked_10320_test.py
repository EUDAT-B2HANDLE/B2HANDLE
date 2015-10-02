"""Testing methods that normally need Handle server read access,
by providing a handle record to replace read access."""

import unittest
import json
import sys
sys.path.append("../..")
from b2handle.handleclient import EUDATHandleClient

class EUDATHandleClientReadaccessFaked10320LOCTestCase(unittest.TestCase):
    '''Testing methods that read the 10320/LOC entry.'''

    def setUp(self):
        self.inst = EUDATHandleClient()

    def tearDown(self):
        pass

    # is_10320LOC_empty

    def test_is_10320LOC_empty_notempty(self):
        """Test if presence of 10320/LOC is detected."""
        handlerecord = json.load(open('resources/handlerecord_with_10320LOC.json'))
        handle = handlerecord['handle']
        answer = self.inst.is_10320LOC_empty(handle, handlerecord)

        self.assertFalse(answer,
            'The record contains a 10320/LOC, but the is_empty does not return False.')

    def test_is_10320LOC_empty_no10320LOC(self):
        """Test if absence of 10320/LOC is detected."""
        handlerecord = json.load(open('resources/handlerecord_without_10320LOC.json'))
        handle = handlerecord['handle']
        answer = self.inst.is_10320LOC_empty(handle, handlerecord)

        self.assertTrue(answer,
            'The record contains no 10320/LOC, but the is_empty does not return True.')

    def test_is_10320LOC_empty_empty10320LOC(self):
        """Test if emptiness of 10320/LOC is detected."""
        handlerecord = json.load(open('resources/handlerecord_with_empty_10320LOC.json'))
        handle = handlerecord['handle']
        answer = self.inst.is_10320LOC_empty(handle, handlerecord)

        self.assertTrue(answer,
            'The record contains an empty 10320/LOC, but the is_empty does not return True.')

    # is_URL_contained_in_1302loc

    def test_is_URL_contained_in_10320LOC_true(self):
        """Test if presence of URL is found in 10320/LOC."""
        handlerecord = json.load(open('resources/handlerecord_with_10320LOC.json'))
        handle = handlerecord['handle']
        answer = self.inst.is_URL_contained_in_10320LOC(handle,
                                                        'http://foo.bar',
                                                        handlerecord)
        val = self.inst.get_value_from_handle(handle, '10320/LOC', handlerecord)
        self.assertTrue(answer,
            'The URL exists in the 10320/LOC, and still the method does not return True:\n'+str(val))

    def test_is_URL_contained_in_10320LOC_false(self):
        """Test if absence of URL is detected in existing 10320/LOC."""
        handlerecord = json.load(open('resources/handlerecord_with_10320LOC.json'))
        handle = handlerecord['handle']
        answer = self.inst.is_URL_contained_in_10320LOC(handle,
                                                        'http://bar.bar',
                                                        handlerecord)
        self.assertFalse(answer,
            'The 10320/LOC does not contain the URL, and still the method does not return False.')

    def test_is_URL_contained_in_inexistent_10320LOC(self):
        """Test if absence of URL is detected if 10320/LOC does not exist."""
        handlerecord = json.load(open('resources/handlerecord_without_10320LOC.json'))
        handle = handlerecord['handle']
        answer = self.inst.is_URL_contained_in_10320LOC(handle,
                                                        'http://whatever.foo',
                                                        handlerecord)
        self.assertFalse(answer,
            'The 10320/LOC does not exist, and still the method does not return False.')

    def test_is_URL_contained_in_empty_10320LOC(self):
        """Test if absence of URL is detected if 10320/LOC is empty."""
        handlerecord = json.load(open('resources/handlerecord_with_empty_10320LOC.json'))
        handle = handlerecord['handle']
        answer = self.inst.is_URL_contained_in_10320LOC(handle,
                                                        'http://whatever.foo',
                                                        handlerecord)
        self.assertFalse(answer,
            'The 10320/LOC is empty, and still the method does not return False.')