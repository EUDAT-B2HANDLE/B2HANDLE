"""Testing methods that normally need Handle server read access,
by providing a handle record to replace read access."""

import sys
if sys.version_info < (2, 7):
    import unittest2 as unittest
else:
    import unittest

import json
import b2handle
from b2handle.handleclient import EUDATHandleClient

# Load some data that is needed for testing
PATH_RES = b2handle.util.get_neighbour_directory(__file__, 'resources')
RECORD_WITH = json.load(open(PATH_RES+'/handlerecord_with_10320LOC_PUBLIC.json'))
RECORD_WITHOUT = json.load(open(PATH_RES+'/handlerecord_without_10320LOC_PUBLIC.json'))
RECORD_WITH_EMPTY = json.load(open(PATH_RES+'/handlerecord_with_empty_10320LOC_PUBLIC.json'))

class EUDATHandleClientReadaccessFaked10320LOCTestCase(unittest.TestCase):
    '''Testing methods that read the 10320/LOC entry.'''

    def setUp(self):
        self.inst = EUDATHandleClient()

    def tearDown(self):
        pass

    # is_10320LOC_empty

    def test_is_10320LOC_empty_notempty(self):
        """Test if presence of 10320/LOC is detected."""
        handlerecord = RECORD_WITH
        handle = handlerecord['handle']
        answer = self.inst.is_10320LOC_empty(handle, handlerecord)

        self.assertFalse(answer,
            'The record contains a 10320/LOC, but the is_empty does not return False.')

    def test_is_10320LOC_empty_no10320LOC(self):
        """Test if absence of 10320/LOC is detected."""
        handlerecord = RECORD_WITHOUT
        handle = handlerecord['handle']
        answer = self.inst.is_10320LOC_empty(handle, handlerecord)

        self.assertTrue(answer,
            'The record contains no 10320/LOC, but the is_empty does not return True.')

    def test_is_10320LOC_empty_empty10320LOC(self):
        """Test if emptiness of 10320/LOC is detected."""
        handlerecord = RECORD_WITH_EMPTY
        handle = handlerecord['handle']
        answer = self.inst.is_10320LOC_empty(handle, handlerecord)

        self.assertTrue(answer,
            'The record contains an empty 10320/LOC, but the is_empty does not return True.')

    # is_URL_contained_in_1302loc

    def test_is_URL_contained_in_10320LOC_true(self):
        """Test if presence of URL is found in 10320/LOC."""
        handlerecord = RECORD_WITH
        handle = handlerecord['handle']
        answer = self.inst.is_URL_contained_in_10320LOC(handle,
                                                        'http://foo.bar',
                                                        handlerecord)
        val = self.inst.get_value_from_handle(handle, '10320/LOC', handlerecord)
        self.assertTrue(answer,
            'The URL exists in the 10320/LOC, and still the method does not return True:\n'+str(val))

    def test_is_URL_contained_in_10320LOC_false(self):
        """Test if absence of URL is detected in existing 10320/LOC."""
        handlerecord = RECORD_WITH
        handle = handlerecord['handle']
        answer = self.inst.is_URL_contained_in_10320LOC(handle,
                                                        'http://bar.bar',
                                                        handlerecord)
        self.assertFalse(answer,
            'The 10320/LOC does not contain the URL, and still the method does not return False.')

    def test_is_URL_contained_in_inexistent_10320LOC(self):
        """Test if absence of URL is detected if 10320/LOC does not exist."""
        handlerecord = RECORD_WITHOUT
        handle = handlerecord['handle']
        answer = self.inst.is_URL_contained_in_10320LOC(handle,
                                                        'http://whatever.foo',
                                                        handlerecord)
        self.assertFalse(answer,
            'The 10320/LOC does not exist, and still the method does not return False.')

    def test_is_URL_contained_in_empty_10320LOC(self):
        """Test if absence of URL is detected if 10320/LOC is empty."""
        handlerecord = RECORD_WITH_EMPTY
        handle = handlerecord['handle']
        answer = self.inst.is_URL_contained_in_10320LOC(handle,
                                                        'http://whatever.foo',
                                                        handlerecord)
        self.assertFalse(answer,
            'The 10320/LOC is empty, and still the method does not return False.')