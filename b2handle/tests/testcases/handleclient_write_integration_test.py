"""Testing methods that need Handle server write access"""

import unittest
import requests
import logging
import json
import sys
import b2handle
from b2handle.handleclient import EUDATHandleClient
from b2handle.handlesystemconnector import HandleSystemConnector
from b2handle.handleexceptions import *
from b2handle.tests.mockresponses import MockResponse
from b2handle.tests.utilities import failure_message, log_start_test_code, log_end_test_code, log_request_response_to_file, log_new_case

REQUESTLOGGER = logging.getLogger('log_all_requests_of_testcases_to_file')
REQUESTLOGGER.addHandler(logging.NullHandler())

# Load some data that is needed for testing
PATH_RES = b2handle.util.get_neighbour_directory(__file__, 'resources')
RESOURCES_FILE = json.load(open(PATH_RES+'/testvalues_for_integration_tests_IGNORE.json'))
# This file is not public, as it contains valid credentials for server
# write access. However, by providing such a file, you can run the tests.
# A template can be found in resources/testvalues_for_integration_tests_template.json


class EUDATHandleClientWriteaccessTestCase(unittest.TestCase):

    def __init__(self, *args, **kwargs):

        REQUESTLOGGER.info("\nINIT of EUDATHandleClientWriteaccessTestCase")

        unittest.TestCase.__init__(self, *args, **kwargs)

        # Read resources from file:
        self.testvalues = RESOURCES_FILE

        # Test values that need to be given by user:
        self.handle = self.testvalues['handle_to_be_modified']
        self.newhandle = self.testvalues['handle_to_be_created']
        
        self.url = self.testvalues['handle_server_url_write']
        self.user = self.testvalues['user']
        self.password = self.testvalues['password']

        # Optional:
        self.https_verify = True
        if 'HTTPS_verify' in self.testvalues:
            self.https_verify = self.testvalues['HTTPS_verify']

        # Others
        self.prefix = self.handle.split('/')[0]
        self.inexistent_handle = self.prefix+'/07e1fbf3-2b72-430a-a035-8584d4eada41'
        self.randompassword = 'some_random_password_shrgfgh345345'
        self.headers = None
        self.connector = HandleSystemConnector(handle_server_url=self.url)

    def setUp(self):

        REQUESTLOGGER.info("\n"+60*"*"+"\nsetUp of EUDATHandleClientWriteaccessTestCase")

        self.inst = EUDATHandleClient.instantiate_with_username_and_password(
            self.url,
            self.user,
            self.password,
            HTTPS_verify=self.https_verify,
            handleowner=self.user)

        authstring = b2handle.utilhandle.create_authentication_string(self.user, self.password)
        self.headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Basic '+authstring
        }

        list_of_all_entries = [
            {
                "index":100,
                "type":"HS_ADMIN",
                "data":{
                    "format":"admin",
                    "value":{
                        "handle":"21.T14999/B2HANDLE_INTEGRATION_TESTS",
                        "index":300,
                        "permissions":"011111110011"
                    }
                }
            },
            {
                "index":111,
                "type": "TEST1",
                "data":{
                    "format":"string",
                    "value":"val1"
                }
            },
            {
                "index":2222,
                "type": "TEST2",
                "data":{
                    "format":"string",
                    "value":"val2"
                }
            },
            {
                "index":333,
                "type": "TEST3",
                "data":{
                    "format":"string",
                    "value":"val3"
                }
            },
            {
                "index":4,
                "type": "TEST4",
                "data":{
                    "format":"string",
                    "value":"val4"
                }
            },
        ]

        testhandle = self.handle
        url = self.connector.make_handle_URL(testhandle)
        veri = self.https_verify
        head = self.headers
        data = json.dumps({'values':list_of_all_entries})
        resp = requests.put(url, data=data, headers=head, verify=veri)
        log_request_response_to_file('PUT', self.handle, url, head, veri, resp)

    def tearDown(self):
        pass

    # modify_handle_value:

    def test_modify_handle_value_corrupted(self):
        """Test exception when trying to modify corrupted handle record."""
        log_new_case("test_modify_handle_value_corrupted")

        # Test variables
        testhandle = self.handle
        head = self.headers
        url = self.connector.make_handle_URL(testhandle)
        # Create corrupted record:
        list_of_all_entries = [
            {
                "index":100,
                "type":"HS_ADMIN",
                "data":{
                    "format":"admin",
                    "value":{
                        "handle":"21.T14999/B2HANDLE_INTEGRATION_TESTS",
                        "index":300,
                        "permissions":"011111110011"
                    }
                }
            },
            {
                "index":111,
                "type": "TEST1",
                "data":{
                    "format":"string",
                    "value":"val1"
                }
            },
            {
                "index":2222,
                "type": "TEST2",
                "data":{
                    "format":"string",
                    "value":"val2"
                }
            },
            {
                "index":333,
                "type": "TEST2",
                "data":{
                    "format":"string",
                    "value":"val3"
                }
            },
            {
                "index":4,
                "type": "TEST4",
                "data":{
                    "format":"string",
                    "value":"val4"
                }
            }
        ]
        data = json.dumps({'values':list_of_all_entries})
        veri = self.https_verify
        resp = requests.put(url, data=data, headers=head, verify=veri)
        log_request_response_to_file('PUT', testhandle, url, head, veri, resp, data)

        # Run code to be tested + check exception:
        log_start_test_code()
        with self.assertRaises(BrokenHandleRecordException):
            self.inst.modify_handle_value(testhandle,
                                          TEST4='new4',
                                          TEST2='new2',
                                          TEST3='new3')
        log_end_test_code()

    def test_modify_handle_value_one(self):
        """Test modifying one existing handle value."""
        log_new_case("test_modify_handle_value_one")

        # Test variables
        testhandle = self.handle

        # Run code to be tested:
        log_start_test_code()
        self.inst.modify_handle_value(testhandle, TEST4='newvalue')
        log_end_test_code()

        # Check desired effects on handle:
        # check if one was modified:
        rec = self.inst.retrieve_handle_record_json(testhandle)
        val = self.inst.get_value_from_handle(testhandle, 'TEST4', rec)
        self.assertEqual(val, 'newvalue',
            'The value did not change.')

        # check if others still there:
        val1 = self.inst.get_value_from_handle(testhandle, 'TEST1', rec)
        val2 = self.inst.get_value_from_handle(testhandle, 'TEST2', rec)
        self.assertEqual(val1, 'val1',
            'The value of "TEST1" should still be "val1".')
        self.assertEqual(val2, 'val2',
            'The value of "TEST2" should still be "val2".')

    def test_modify_handle_value_several(self):
        """Test modifying several existing handle values."""
        log_new_case("test_modify_handle_value_several")

        # Test variables
        testhandle = self.handle

        # Run code to be tested:
        log_start_test_code()
        self.inst.modify_handle_value(testhandle,
                                      TEST4='new4',
                                      TEST2='new2',
                                      TEST3='new3')
        log_end_test_code()

        # Check desired effects on handle:
        # check if three values were modified:
        rec = self.inst.retrieve_handle_record_json(testhandle)
        val2 = self.inst.get_value_from_handle(testhandle, 'TEST2', rec)
        val3 = self.inst.get_value_from_handle(testhandle, 'TEST3', rec)
        val4 = self.inst.get_value_from_handle(testhandle, 'TEST4', rec)
        self.assertEqual(val2, 'new2',
            'The value of "TEST2" was not changed to "new2".')
        self.assertEqual(val3, 'new3',
            'The value of "TEST3" was not changed to "new3".')
        self.assertEqual(val4, 'new4',
            'The value of "TEST4" was not changed to "new4".')

        # check if one value remained unchanged:
        val1 = self.inst.get_value_from_handle(testhandle, 'TEST1', rec)
        self.assertEqual(val1, 'val1',
            'The value of "TEST1" should still be "val1".')

    def test_modify_handle_value_several_inexistent(self):
        """Test modifying several existing handle values, one of them inexistent."""
        log_new_case("test_modify_handle_value_several_inexistent")
        
        # Test variables
        testhandle = self.handle

        # Run code to be tested:
        log_start_test_code()
        self.inst.modify_handle_value(testhandle,
                                      TEST4='new4',
                                      TEST2='new2',
                                      TEST100='new100')
        log_end_test_code()

        # Check desired effects on handle:
        # check if three values were modified:
        rec = self.inst.retrieve_handle_record_json(testhandle)
        val2   = self.inst.get_value_from_handle(testhandle, 'TEST2', rec)
        val100 = self.inst.get_value_from_handle(testhandle, 'TEST100', rec)
        val4   = self.inst.get_value_from_handle(testhandle, 'TEST4', rec)
        self.assertEqual(val100, 'new100',
            'The value of "TEST100" was not created and set to "new100".')
        self.assertEqual(val2, 'new2',
            'The value of "TEST2" was not changed to "new2".')
        self.assertEqual(val4, 'new4',
            'The value of "TEST4" was not changed to "new4".')

        # check if one value remained unchanged:
        val1 = self.inst.get_value_from_handle(testhandle, 'TEST1', rec)
        self.assertEqual(val1, 'val1',
            'The value of "TEST1" should still be "val1".')

    def test_modify_handle_value_without_authentication(self):
        """Test if exception when not authenticated."""
        log_new_case("test_modify_handle_value_without_authentication")

        # Test variables
        testhandle = self.handle
        inst_readonly = EUDATHandleClient(self.url, HTTPS_verify=self.https_verify)

        # Run code to be tested + check exception:
        log_start_test_code()
        with self.assertRaises(HandleAuthenticationError):
            inst_readonly.modify_handle_value(testhandle, foo='bar')
        log_end_test_code()

    def test_modify_handle_value_HS_ADMIN(self):
        """Test exception when trying to modify HS_ADMIN."""
        log_new_case("test_modify_handle_value_HS_ADMIN")

        # Test variables
        testhandle = self.handle

        # Run code to be tested + check exception:
        log_start_test_code()
        with self.assertRaises(IllegalOperationException):
            self.inst.modify_handle_value(testhandle, HS_ADMIN='please let me in!')
        log_end_test_code()

    # register_handle:

    def test_register_handle(self):
        """Test registering a new handle with various types of values."""
        log_new_case("test_register_handle")

        # Test variables
        testhandle = self.newhandle
        additional_URLs = ['http://bar.bar', 'http://foo.foo']

        # Run code to be tested:
        log_start_test_code()
        handle_returned = self.inst.register_handle(testhandle,
                                                    location='http://foo.bar',
                                                    checksum='123456',
                                                    additional_URLs=additional_URLs,
                                                    FOO='foo',
                                                    BAR='bar')
        log_end_test_code()

        # Check desired effects on handle:
        # Check if content was written ok:
        rec = self.inst.retrieve_handle_record_json(testhandle)
        val1 = self.inst.get_value_from_handle(testhandle, 'BAR', rec)
        val2 = self.inst.get_value_from_handle(testhandle, 'FOO', rec)
        val3 = self.inst.get_value_from_handle(testhandle, 'URL', rec)
        val4 = self.inst.get_value_from_handle(testhandle, 'CHECKSUM', rec)
        contained1 = self.inst.is_URL_contained_in_10320LOC(testhandle, 'http://bar.bar', rec)
        contained2 = self.inst.is_URL_contained_in_10320LOC(testhandle, 'http://foo.foo', rec)

        self.assertEqual(handle_returned, testhandle,
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
        handle = self.newhandle
        url = self.connector.make_handle_URL(self.newhandle)
        head = self.headers
        veri = self.https_verify
        resp = requests.delete(url, headers=head, verify=veri)
        log_request_response_to_file('DELETE', handle, url, head, veri, resp)
        rec = self.inst.retrieve_handle_record_json(self.newhandle)

        self.assertEqual(resp.status_code, 200,
            'Deleting did not return a HTTP 200 code, but: %s, %s' % (resp,resp.content))
        self.assertIsNone(rec,
            'The deleted record should return None.')

    def test_register_handle_already_exists(self):
        """Test if overwrite=False prevents handle overwriting."""
        log_new_case("test_register_handle_already_exists")

        # Test variables
        testhandle = self.handle

        # Run code to be tested + check exception:
        log_start_test_code()
        with self.assertRaises(HandleAlreadyExistsException):
            self.inst.register_handle(testhandle,
                                      'http://foo.foo',
                                      TEST1='I am just an illusion.')
        log_end_test_code()

        # Check if nothing was changed:
        rec = self.inst.retrieve_handle_record_json(testhandle)
        val1 = self.inst.get_value_from_handle(testhandle, 'TEST1', rec)
        self.assertEqual(val1, 'val1',
            'The handle should not be overwritten, thus this value should have stayed the same.')

    def test_generate_and_register_handle(self):
        """Test generating and registering a new handle with various types of values."""
        log_new_case("test_generate_and_register_handle")

        # Test variables
        additional_URLs = ['http://bar.bar', 'http://foo.foo']
        prefix = self.prefix

        # Run code to be tested:
        log_start_test_code()
        handle_returned = self.inst.generate_and_register_handle(prefix=prefix,
                                                    location='http://foo.bar',
                                                    checksum='123456',
                                                    additional_URLs=additional_URLs,
                                                    FOO='foo',
                                                    BAR='bar')
        log_end_test_code()

        # Check desired effects on handle:
        rec = self.inst.retrieve_handle_record_json(handle_returned)
        val1 = self.inst.get_value_from_handle(handle_returned, 'BAR', rec)
        val2 = self.inst.get_value_from_handle(handle_returned, 'FOO', rec)
        val3 = self.inst.get_value_from_handle(handle_returned, 'URL', rec)
        val4 = self.inst.get_value_from_handle(handle_returned, 'CHECKSUM', rec)
        contained1 = self.inst.is_URL_contained_in_10320LOC(handle_returned, 'http://bar.bar', rec)
        contained2 = self.inst.is_URL_contained_in_10320LOC(handle_returned, 'http://foo.foo', rec)

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
        self.assertIn(prefix, handle_returned,
            'The returned handle does not contain the given prefix.')

        # Delete again (and check if was deleted):
        url = self.connector.make_handle_URL(handle_returned)
        head = self.headers
        veri = self.https_verify
        resp = requests.delete(url, headers=head, verify=veri)
        log_request_response_to_file('DELETE', handle_returned, url, head, veri, resp)
        rec = self.inst.retrieve_handle_record_json(handle_returned)

        self.assertEqual(resp.status_code, 200,
            'Deleting did not return a HTTP 200 code.')
        self.assertIsNone(rec,
            'The deleted record should return None.')

    # delete_handle_value:

    def test_delete_handle_value_one_entry(self):
        """Test deleting one entry from a record."""
        log_new_case("test_delete_handle_value_one_entry")

        # Test variables
        testhandle = self.handle

        # Run code to be tested:
        log_start_test_code()
        self.inst.delete_handle_value(testhandle, 'TEST1')
        log_end_test_code()

        # Check desired effects on handle:
        rec = self.inst.retrieve_handle_record_json(testhandle)
        val = self.inst.get_value_from_handle(testhandle, 'TEST1', rec)
        indices = self.inst.get_handlerecord_indices_for_key('TEST1', rec['values'])
        self.assertIsNone(val,
            'The value for the deleted entry should be None.')
        self.assertEqual(len(indices), 0,
            'There should be no index for the deleted entry.')

    def test_delete_handle_value_several_occurrences(self):
        """Test trying to delete from a corrupted handle record."""
        log_new_case("test_delete_handle_value_several_occurrences")
        
        # Test variables
        testhandle = self.handle

        # Call the method to be tested:
        log_start_test_code()
        self.inst.delete_handle_value(testhandle, 'TEST2')
        log_end_test_code()

        # Check desired effects on handle:
        rec = self.inst.retrieve_handle_record_json(testhandle)
        val1 = self.inst.get_value_from_handle(testhandle, 'TEST2', rec)
        indices1 = self.inst.get_handlerecord_indices_for_key('TEST2', rec['values'])

        self.assertIsNone(val1,
            'The value for the deleted entry should be None.')
        self.assertEqual(len(indices1), 0,
            'There should be no index for the deleted entry.')

    def test_delete_handle_value_several_entries(self):
        """Test deleting several entries from a record."""
        log_new_case("test_delete_handle_value_several_entries")

        # Test variables
        testhandle = self.handle

        # Run code to be tested:
        log_start_test_code()
        self.inst.delete_handle_value(testhandle, ['TEST1', 'TEST2'])
        log_end_test_code()

        # Check desired effects on handle:
        rec = self.inst.retrieve_handle_record_json(testhandle)
        val1 = self.inst.get_value_from_handle(testhandle, 'TEST1', rec)
        val2 = self.inst.get_value_from_handle(testhandle, 'TEST2', rec)
        indices1 = self.inst.get_handlerecord_indices_for_key('TEST1', rec['values'])
        indices2 = self.inst.get_handlerecord_indices_for_key('TEST2', rec['values'])

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
        log_new_case("test_delete_handle_value_inexistent_entry")

        # Test variables
        testhandle = self.handle
        key = 'TEST100'

        # Run code to be tested:
        log_start_test_code()
        self.inst.delete_handle_value(testhandle, key)
        log_end_test_code()

        # Check desired effects on handle:
        rec = self.inst.retrieve_handle_record_json(testhandle)
        val = self.inst.get_value_from_handle(testhandle, key, rec)
        indices = self.inst.get_handlerecord_indices_for_key(key, rec['values'])
        self.assertIsNone(val,
            'The index for the deleted entry should be None.')
        self.assertEqual(len(indices), 0,
            'There should be no index for the deleted entry.')

    def test_delete_handle_value_several_entries_one_nonexistent(self):
        """Test deleting several entries from a record, one of them does not exist."""
        log_new_case("test_delete_handle_value_several_entries_one_nonexistent")


        # Test variables
        testhandle = self.handle

        # Run code to be tested:
        log_start_test_code()
        self.inst.delete_handle_value(testhandle, ['TEST1', 'TEST100'])
        log_end_test_code()

        # Check desired effects on handle:
        rec = self.inst.retrieve_handle_record_json(testhandle)
        val = self.inst.get_value_from_handle(testhandle, 'TEST1', rec)
        indices = self.inst.get_handlerecord_indices_for_key('TEST1', rec['values'])
        self.assertIsNone(val,
            'The index for the deleted entry should be None.')
        self.assertEqual(len(indices), 0,
            'There should be no index for the deleted entry.')

    # delete handle:

    def test_delete_handle_normal(self):
        """Test deleting an entire record."""
        log_new_case("test_delete_handle_normal")

        # Test variables
        testhandle = self.handle
        
        # Run code to be tested:
        log_start_test_code()
        resp = self.inst.delete_handle(testhandle)
        log_end_test_code()

        # Check desired effects on handle:
        # Check if handle really deleted:
        rec = self.inst.retrieve_handle_record_json(testhandle)
        self.assertIsNone(rec,
            'Record should be None after deletion, but is: '+str(resp))

    def test_delete_handle_too_many_args(self):
        """Test deleting an entire record, but we pass more arguments to the method."""
        log_new_case("test_delete_handle_too_many_args")

        # Test variables
        testhandle = self.handle

        # Run code to be tested + check exception:
        log_start_test_code()
        with self.assertRaises(TypeError):
            self.inst.delete_handle(testhandle, 'TEST1')
        log_end_test_code()

    def test_delete_handle_inexistent(self):
        """Test deleting an inexistent handle."""
        log_new_case("test_delete_handle_inexistent")

        # Test variables
        testhandle = self.inexistent_handle
        
        # Run code to be tested:
        log_start_test_code()
        resp = self.inst.delete_handle(self.inexistent_handle)
        log_end_test_code()

        # Check desired effects on handle:
        self.assertIsNone(resp,
            'Response (when deleting inexistent handle) should be None, but is: '+str(resp))

