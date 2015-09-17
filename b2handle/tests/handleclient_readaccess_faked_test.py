"""Testing methods that normally need Handle server read access,
by providing a handle record to replace read access."""

import unittest
import json
import sys
sys.path.append("../..")
from b2handle.handleclient import EUDATHandleClient

class EUDATHandleClientReadaccessFakedTestCase(unittest.TestCase):
    '''Testing methods for retrieving values and indices.'''

    def setUp(self):
        self.inst = EUDATHandleClient()
        self.handlerecord_json = {
            "responseCode":"1",
            "handle":"testprefix/testhandle",
            "values":
            [
                {
                    "index":111,
                    "type":"URL",
                    "data": {
                        "format":"string",
                        "value":"www.url.foo"
                    }
                },
                {
                    "index":222,
                    "type":"testtype",
                    "data":{
                        "format":"string",
                        "value":"testvalue"
                    }
                },
                {
                    "index":333,
                    "type":"testtype_duplicate",
                    "data":{
                        "format":"string",
                        "value":"testvalue"
                    }
                },
                {
                    "index":444,
                    "type":"testtype_duplicate",
                    "data":{
                        "format":"string",
                        "value":"testvalue"
                    }
                },
            ]
        }

    def tearDown(self):
        pass

    # get_value_from_handle

    def test_get_value_from_handle_normal(self):
        """Test retrieving a specific value from a handle record."""

        handlerecord = json.load(open('resources/handlerecord_for_reading.json'))
        handle = handlerecord['handle']

        val = self.inst.get_value_from_handle(handle,
                                              'test1',
                                              handlerecord)
        self.assertEquals(val, 'val1',
            'The value of "test1" should be "val1".')

    def test_get_value_from_handle_inexistentvalue(self):
        """Test retrieving an inexistent value from a handle record."""

        handlerecord = json.load(open('resources/handlerecord_for_reading.json'))
        handle = handlerecord['handle']

        val = self.inst.get_value_from_handle(handle,
                                              'test100',
                                              handlerecord)
        self.assertIsNone(val,
            'The value of "test100" should be None.')

    def test_get_value_from_handle_HS_ADMIN(self):
        """Test retrieving an HS_ADMIN value from a handle record."""

        handlerecord = json.load(open('resources/handlerecord_for_reading.json'))
        handle = handlerecord['handle']

        val = self.inst.get_value_from_handle(handle,
                                              'HS_ADMIN',
                                              handlerecord)
        self.assertIn('handle', val,
            'The HS_ADMIN has no entry "handle".')
        self.assertIn('index', val,
            'The HS_ADMIN has no entry "index".')
        self.assertIn('permissions', val,
            'The HS_ADMIN has no entry "permissions".')
        syntax_ok = self.inst.check_handle_syntax(val['handle'])
        self.assertTrue(syntax_ok,
            'The handle in HS_ADMIN is not well-formatted.')
        self.assertIsInstance(val['index'], (int, long),
            'The index of the HS_ADMIN is not an integer.')
        self.assertEqual(str(val['permissions']).replace('0','').replace('1',''), '',
            'The permission value in the HS_ADMIN contains not just 0 and 1.')

    def test_get_value_from_handle_duplicatekey(self):
        """Test retrieving a value of a duplicate key."""

        handlerecord = json.load(open('resources/handlerecord_for_reading.json'))
        handle = handlerecord['handle']

        val = self.inst.get_value_from_handle(handle,
                                              'testdup',
                                              handlerecord)
        self.assertIn(val, ("dup1", "dup2"),
            'The value of the duplicate key "testdup" should be "dup1" or "dup2".')

    # retrieve_handle_record

    def test_retrieve_handle_record_normal(self):

        handlerecord = json.load(open('resources/handlerecord_for_reading.json'))
        handle = handlerecord['handle']

        dict_record = self.inst.retrieve_handle_record(handle, handlerecord)

        self.assertIn('test1', dict_record,
            'Key "test1" not in handlerecord dictionary!')
        self.assertIn('test2', dict_record,
            'Key "test2" not in handlerecord dictionary!')
        self.assertIn('testdup', dict_record,
            'Key "testdup" not in handlerecord dictionary!')
        self.assertIn('HS_ADMIN', dict_record,
            'Key "HS_ADMIN" not in handlerecord dictionary!')

        self.assertEqual(dict_record['test1'], 'val1',
            'The value of "test1" is not "val1.')
        self.assertEqual(dict_record['test2'], 'val2',
            'The value of "test2" is not "val2.')
        self.assertIn(dict_record['testdup'], ("dup1", "dup2"),
            'The value of the duplicate key "testdup" should be "dup1" or "dup2".')
        self.assertIn('permissions', dict_record['HS_ADMIN'],
            'The HS_ADMIN has no permissions: '+dict_record['HS_ADMIN'])

        self.assertEqual(len(dict_record), 4,
            'The record should have a length of 5 (as the duplicate is ignored.')


    # get_handlerecord_indices_for_key

    def test_get_indices_for_key_normal(self):
        """Test getting the indices for a specific key."""

        handlerecord = json.load(open('resources/handlerecord_for_reading.json'))
        handle = handlerecord['handle']

        indices = self.inst.get_handlerecord_indices_for_key('test1', handlerecord['values'])
        self.assertEqual(len(indices),1,
            'There is more or less than 1 index!')
        self.assertEqual(indices[0], 3,
            'The index of "test1" is not 3.')

    def test_get_indices_for_key_duplicatekey(self):
        """Test getting the indices for a duplicate key."""

        handlerecord = json.load(open('resources/handlerecord_for_reading.json'))
        handle = handlerecord['handle']

        indices = self.inst.get_handlerecord_indices_for_key('testdup', handlerecord['values'])
        self.assertEqual(len(indices),2,
            'There is more or less than 2 indices!')
        self.assertIn(5, indices,
            '5 is not in indices for key "testdup".')
        self.assertIn(6, indices,
            '6 is not in indices for key "testdup".')

    def test_get_indices_for_key_inexistentkey(self):
        """Test getting the indices for an inexistent key."""

        handlerecord = json.load(open('resources/handlerecord_for_reading.json'))
        handle = handlerecord['handle']

        indices = self.inst.get_handlerecord_indices_for_key('test100', handlerecord['values'])
        self.assertEqual(len(indices),0,
            'There is more than 0 index!')
        self.assertEqual(indices,[],
            'Indices should be an empty list!')