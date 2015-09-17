"""Testing methods that normally need Handle server read access,
by providing a handle record to replace read access."""

import unittest
import json
import sys
sys.path.append("../..")
from b2handle.handleclient import EUDATHandleClient

class EUDATHandleClientReadaccessFaked10320locTestCase(unittest.TestCase):
    '''Testing methods that read the 10320/loc entry.'''

    def setUp(self):
        self.inst = EUDATHandleClient()

    def tearDown(self):
        pass

    # is_10320loc_empty

    def test_is_10320loc_empty_notempty(self):
        """Test if presence of 10320/loc is detected."""
        handlerecord = json.load(open('resources/handlerecord_with_10320loc.json'))
        handle = handlerecord['handle']
        answer = self.inst.is_10320loc_empty(handle, handlerecord)

        self.assertFalse(answer,
            'The record contains a 10320/loc, but the is_empty does not return False.')

    def test_is_10320loc_empty_no10320loc(self):
        """Test if absence of 10320/loc is detected."""
        handlerecord = json.load(open('resources/handlerecord_without_10320loc.json'))
        handle = handlerecord['handle']
        answer = self.inst.is_10320loc_empty(handle, handlerecord)

        self.assertTrue(answer,
            'The record contains no 10320/loc, but the is_empty does not return True.')

    def test_is_10320loc_empty_empty10320loc(self):
        """Test if emptiness of 10320/loc is detected."""
        handlerecord = json.load(open('resources/handlerecord_with_empty_10320loc.json'))
        handle = handlerecord['handle']
        answer = self.inst.is_10320loc_empty(handle, handlerecord)

        self.assertTrue(answer,
            'The record contains an empty 10320/loc, but the is_empty does not return True.')

    # is_URL_contained_in_1302loc

    def test_is_URL_contained_in_10320loc_true(self):
        """Test if presence of URL is found in 10320/loc."""
        handlerecord = json.load(open('resources/handlerecord_with_10320loc.json'))
        handle = handlerecord['handle']
        answer = self.inst.is_URL_contained_in_10320loc(handle,
                                                        'http://foo.bar',
                                                        handlerecord)
        self.assertTrue(answer,
            'The URL exists in the 10320/loc, and still the method does not return True.')

    def test_is_URL_contained_in_10320loc_false(self):
        """Test if absence of URL is detected in existing 10320/loc."""
        handlerecord = json.load(open('resources/handlerecord_with_10320loc.json'))
        handle = handlerecord['handle']
        answer = self.inst.is_URL_contained_in_10320loc(handle,
                                                        'http://bar.bar',
                                                        handlerecord)
        self.assertFalse(answer,
            'The 10320/loc does not contain the URL, and still the method does not return False.')

    def test_is_URL_contained_in_inexistent_10320loc(self):
        """Test if absence of URL is detected if 10320/loc does not exist."""
        handlerecord = json.load(open('resources/handlerecord_without_10320loc.json'))
        handle = handlerecord['handle']
        answer = self.inst.is_URL_contained_in_10320loc(handle,
                                                        'http://whatever.foo',
                                                        handlerecord)
        self.assertFalse(answer,
            'The 10320/loc does not exist, and still the method does not return False.')

    def test_is_URL_contained_in_empty_10320loc(self):
        """Test if absence of URL is detected if 10320/loc is empty."""
        handlerecord = json.load(open('resources/handlerecord_with_empty_10320loc.json'))
        handle = handlerecord['handle']
        answer = self.inst.is_URL_contained_in_10320loc(handle,
                                                        'http://whatever.foo',
                                                        handlerecord)
        self.assertFalse(answer,
            'The 10320/loc is empty, and still the method does not return False.')