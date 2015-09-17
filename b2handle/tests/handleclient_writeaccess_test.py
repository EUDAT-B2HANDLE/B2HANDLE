"""Testing methods that need Handle server write access"""

import unittest
import requests
import logging
import json
import sys
sys.path.append("../..")
from b2handle.handleclient import EUDATHandleClient
from b2handle.handleexceptions import HandleAlreadyExistsException
from b2handle.handleexceptions import BrokenHandleRecordException
from b2handle.handleexceptions import IllegalOperationException
from b2handle.handleexceptions import HandleAuthentificationError

import logging
LOGGER = logging.getLogger(__name__)
LOGGER.addHandler(logging.NullHandler())

RESOURCES_FILE = 'resources/testvalues_for_integration_tests_IGNORE.json'


class EUDATHandleClientWriteaccessTestCase(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        unittest.TestCase.__init__(self, *args, **kwargs)
        self.testvalues = json.load(open(RESOURCES_FILE))
        self.handle = self.testvalues['handle_to_be_modified']
        self.newhandle = self.testvalues['handle_to_be_created']
        self.inexistent_handle = self.testvalues['handle_doesnotexist']
        self.url_https = self.testvalues['url_https']
        self.user = self.testvalues['user']
        self.password = self.testvalues['password']
        self.user_no_index = self.testvalues['user_without_index']
        self.inexistent_user = self.testvalues['nonexistent_user']
        self.handle_withloc = self.testvalues['handle_with_10320loc']
        self.handle_withoutloc = self.testvalues['handle_without_10320loc']
        self.verify = self.testvalues['HTTP_verify']
        self.prefix = self.testvalues['prefix']
        self.randompassword = 'some_random_password_shrgfgh345345'
        self.headers = None


    def setUp(self):
        self.inst = EUDATHandleClient.instantiate_with_username_and_password(
            self.url_https,
            self.user,
            self.password,
            HTTP_verify=False)
        authstring = self.inst.create_authentication_string(self.user, self.password)
        self.headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Basic '+authstring
        }

        list_of_all_entries = [
            {
                "index":111,
                "type":"test1",
                "data":{
                    "format":"string",
                    "value":"val1"
                }
            },
            {
                "index":2222,
                "type":"test2",
                "data":{
                    "format":"string",
                    "value":"val2"
                }
            },
            {
                "index":333,
                "type":"test3",
                "data":{
                    "format":"string",
                    "value":"val3"
                }
            },
            {
                "index":4,
                "type":"test4",
                "data":{
                    "format":"string",
                    "value":"val4"
                }
            },
        ]
        url = self.inst.make_handle_URL(self.handle)
        data = json.dumps({'values':list_of_all_entries})
        #requests.put(url, data=data, headers=self.headers, verify=False)
        requests.put(url, data=data, headers=self.headers, verify=False)

    def tearDown(self):
        pass

    # Modify handle values:

    def test_modify_handle_value_corrupted(self):
        """Test exception when trying to modify corrupted handle record."""

        # Create corrupted record:
        list_of_all_entries = [
            {
                "index":111,
                "type":"test1",
                "data":{
                    "format":"string",
                    "value":"val1"
                }
            },
            {
                "index":2222,
                "type":"test2",
                "data":{
                    "format":"string",
                    "value":"val2"
                }
            },
            {
                "index":333,
                "type":"test2",
                "data":{
                    "format":"string",
                    "value":"val3"
                }
            },
            {
                "index":4,
                "type":"test4",
                "data":{
                    "format":"string",
                    "value":"val4"
                }
            }
        ]
        url = self.inst.make_handle_URL(self.handle)
        data = json.dumps({'values':list_of_all_entries})
        requests.put(url, data=data, headers=self.headers, verify=False)

        # Modifying corrupted raises exception:
        with self.assertRaises(BrokenHandleRecordException):
            self.inst.modify_handle_value(self.handle,
                                          test4='new4',
                                          test2='new2',
                                          test3='new3')

    def test_modify_handle_value_one(self):
        """Test modifying one existing handle value."""

        self.inst.modify_handle_value(self.handle, test4='newvalue')

        # check if one was modified:
        rec = self.inst.retrieve_handle_record_json(self.handle)
        val = self.inst.get_value_from_handle(self.handle, 'test4', rec)
        self.assertEqual(val, 'newvalue',
            'The value did not change.')

        # check if others still there:
        val1 = self.inst.get_value_from_handle(self.handle, 'test1', rec)
        val2 = self.inst.get_value_from_handle(self.handle, 'test2', rec)
        self.assertEqual(val1, 'val1',
            'The value of "test1" should still be "val1".')
        self.assertEqual(val2, 'val2',
            'The value of "test2" should still be "val2".')

    def test_modify_handle_value_several(self):
        """Test modifying several existing handle values."""
        self.inst.modify_handle_value(self.handle,
                                      test4='new4',
                                      test2='new2',
                                      test3='new3')

        # check if three values were modified:
        rec = self.inst.retrieve_handle_record_json(self.handle)
        val2 = self.inst.get_value_from_handle(self.handle, 'test2', rec)
        val3 = self.inst.get_value_from_handle(self.handle, 'test3', rec)
        val4 = self.inst.get_value_from_handle(self.handle, 'test4', rec)
        self.assertEqual(val2, 'new2',
            'The value of "test2" was not changed to "new2".')
        self.assertEqual(val3, 'new3',
            'The value of "test3" was not changed to "new3".')
        self.assertEqual(val4, 'new4',
            'The value of "test4" was not changed to "new4".')

        # check if one value remained unchanged:
        val1 = self.inst.get_value_from_handle(self.handle, 'test1', rec)
        self.assertEqual(val1, 'val1',
            'The value of "test1" should still be "val1".')

    def test_modify_handle_value_several_inexistent(self):
        """Test modifying several existing handle values, one of them inexistent."""
        self.inst.modify_handle_value(self.handle,
                                      test4='new4',
                                      test2='new2',
                                      test100='new100')

        # check if three values were modified:
        rec = self.inst.retrieve_handle_record_json(self.handle)
        val2   = self.inst.get_value_from_handle(self.handle, 'test2', rec)
        val100 = self.inst.get_value_from_handle(self.handle, 'test100', rec)
        val4   = self.inst.get_value_from_handle(self.handle, 'test4', rec)
        self.assertEqual(val100, 'new100',
            'The value of "test100" was not created and set to "new100".')
        self.assertEqual(val2, 'new2',
            'The value of "test2" was not changed to "new2".')
        self.assertEqual(val4, 'new4',
            'The value of "test4" was not changed to "new4".')

        # check if one value remained unchanged:
        val1 = self.inst.get_value_from_handle(self.handle, 'test1', rec)
        self.assertEqual(val1, 'val1',
            'The value of "test1" should still be "val1".')
    
    def test_modify_handle_value_without_authentication(self):
        """Test if exception when not authenticated."""
        inst_readonly = EUDATHandleClient(self.url_https, HTTP_verify=False)
        with self.assertRaises(HandleAuthentificationError):
            inst_readonly.modify_handle_value(self.handle, foo='bar')

    def test_modify_handle_value_HS_ADMIN(self):
        """Test exception when trying to modify HS_ADMIN."""
        with self.assertRaises(IllegalOperationException):
            self.inst.modify_handle_value(self.handle, HS_ADMIN='please let me in!')

    # Register handle:

    def test_register_handle(self):
        """Test registering a new handle with various types of values."""

        # Write new handle:
        additional_URLs = ['http://bar.bar', 'http://foo.foo']
        handle_returned = self.inst.register_handle(self.newhandle,
                                                    location='http://foo.bar',
                                                    checksum='123456',
                                                    additional_URLs=additional_URLs,
                                                    overwrite=True,
                                                    foo='foo',
                                                    bar='bar')

        # Check if content was written ok:
        rec = self.inst.retrieve_handle_record_json(self.newhandle)
        val1 = self.inst.get_value_from_handle(self.newhandle, 'bar', rec)
        val2 = self.inst.get_value_from_handle(self.newhandle, 'foo', rec)
        val3 = self.inst.get_value_from_handle(self.newhandle, 'URL', rec)
        val4 = self.inst.get_value_from_handle(self.newhandle, 'checksum', rec)
        contained1 = self.inst.is_URL_contained_in_10320loc(self.newhandle, 'http://bar.bar', rec)
        contained2 = self.inst.is_URL_contained_in_10320loc(self.newhandle, 'http://foo.foo', rec)


        self.assertEqual(handle_returned, self.newhandle,
            'The handle returned by the create-method was not the one passed to it.')
        self.assertEqual(val1, 'bar',
            'The value "bar" was not inserted.')
        self.assertEqual(val2, 'foo',
            'The value "foo" was not inserted.')
        self.assertEqual(val3, 'http://foo.bar',
            'The value "http://foo.bar" was not inserted.')
        self.assertEqual(val4, '123456',
            'The value "123456" was not inserted.')
        self.assertTrue(contained1,
            'A specified additional URL was not inserted.')
        self.assertTrue(contained2,
            'A specified additional URL was not inserted.')

        # Delete again (and check if was deleted):
        url = self.inst.make_handle_URL(self.newhandle)
        resp = requests.delete(url, headers=self.headers, verify=False)
        rec = self.inst.retrieve_handle_record_json(self.newhandle)

        self.assertEqual(resp.status_code, 200,
            'Deleting did not return a HTTP 200 code.')
        self.assertIsNone(rec,
            'The deleted record should return None.')

    def test_register_handle_already_exists(self):
        """Test if overwrite=False prevents handle overwriting."""
        with self.assertRaises(HandleAlreadyExistsException):
            self.inst.register_handle(self.handle,
                                      'http://foo.foo',
                                      test1='I am just an illusion.',
                                      overwrite=False)

        # Check if nothing was changed:
        rec = self.inst.retrieve_handle_record_json(self.handle)
        val1 = self.inst.get_value_from_handle(self.handle, 'test1', rec)
        self.assertEqual(val1, 'val1',
            'The handle should not be overwritten, thus this value should have stayed the same.')

    def test_generate_and_register_handle(self):
        """Test generating and registering a new handle with various types of values."""

        # Write new handle:
        additional_URLs = ['http://bar.bar', 'http://foo.foo']
        handle_returned = self.inst.generate_and_register_handle(prefix=self.prefix,
                                                    location='http://foo.bar',
                                                    checksum='123456',
                                                    additional_URLs=additional_URLs,
                                                    foo='foo',
                                                    bar='bar')

        # Check if content was written ok:
        rec = self.inst.retrieve_handle_record_json(handle_returned)
        val1 = self.inst.get_value_from_handle(handle_returned, 'bar', rec)
        val2 = self.inst.get_value_from_handle(handle_returned, 'foo', rec)
        val3 = self.inst.get_value_from_handle(handle_returned, 'URL', rec)
        val4 = self.inst.get_value_from_handle(handle_returned, 'checksum', rec)
        contained1 = self.inst.is_URL_contained_in_10320loc(handle_returned, 'http://bar.bar', rec)
        contained2 = self.inst.is_URL_contained_in_10320loc(handle_returned, 'http://foo.foo', rec)

        self.assertEqual(val1, 'bar',
            'The value "bar" was not inserted.')
        self.assertEqual(val2, 'foo',
            'The value "foo" was not inserted.')
        self.assertEqual(val3, 'http://foo.bar',
            'The value "http://foo.bar" was not inserted.')
        self.assertEqual(val4, '123456',
            'The value "123456" was not inserted.')
        self.assertTrue(contained1,
            'A specified additional URL was not inserted.')
        self.assertTrue(contained2,
            'A specified additional URL was not inserted.')
        self.assertIn(self.prefix, handle_returned,
            'The returned handle does not contain the given prefix.')

        # Delete again (and check if was deleted):
        url = self.inst.make_handle_URL(handle_returned)
        resp = requests.delete(url, headers=self.headers, verify=False)
        rec = self.inst.retrieve_handle_record_json(handle_returned)

        self.assertEqual(resp.status_code, 200,
            'Deleting did not return a HTTP 200 code.')
        self.assertIsNone(rec,
            'The deleted record should return None.')

    # Delete handle values:

    def test_delete_handle_value_one_entry(self):
        """Test deleting one entry from a record."""

        self.inst.delete_handle_value(self.handle, 'test1')

        rec = self.inst.retrieve_handle_record_json(self.handle)
        val = self.inst.get_value_from_handle(self.handle, 'test1', rec)
        indices = self.inst.get_handlerecord_indices_for_key('test1', rec['values'])
        self.assertIsNone(val,
            'The value for the deleted entry should be None.')
        self.assertEqual(len(indices), 0,
            'There should be no index for the deleted entry.')

    def test_delete_handle_value_several_entries(self):
        """Test deleting several entries from a record."""
        self.inst.delete_handle_value(self.handle, ['test1', 'test2'])
        rec = self.inst.retrieve_handle_record_json(self.handle)
        val1 = self.inst.get_value_from_handle(self.handle, 'test1', rec)
        val2 = self.inst.get_value_from_handle(self.handle, 'test2', rec)
        indices1 = self.inst.get_handlerecord_indices_for_key('test1', rec['values'])
        indices2 = self.inst.get_handlerecord_indices_for_key('test2', rec['values'])

        self.assertIsNone(val1,
            'The value for the deleted entry should be None.')
        self.assertIsNone(val2,
            'The value for the deleted entry should be None.')
        self.assertEqual(len(indices1), 0,
            'There should be no index for the deleted entry.')
        self.assertEqual(len(indices2), 0,
            'There should be no index for the deleted entry.')

    def test_delete_handle_value_inexistent_entry(self):
        """Test deleting one entry from a record."""
        key = 'test100'
        self.inst.delete_handle_value(self.handle, key)
        rec = self.inst.retrieve_handle_record_json(self.handle)
        val = self.inst.get_value_from_handle(self.handle, key, rec)
        indices = self.inst.get_handlerecord_indices_for_key(key, rec['values'])
        self.assertIsNone(val,
            'The index for the deleted entry should be None.')
        self.assertEqual(len(indices), 0,
            'There should be no index for the deleted entry.')

