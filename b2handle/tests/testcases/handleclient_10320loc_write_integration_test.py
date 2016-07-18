"""Testing methods that need Handle server write access"""

import sys
if sys.version_info < (2, 7):
    import unittest2 as unittest
else:
    import unittest

import requests
import json
import logging
import b2handle
from b2handle.handleclient import EUDATHandleClient
from b2handle.handlesystemconnector import HandleSystemConnector
from b2handle.handleexceptions import *
from b2handle.tests.utilities import failure_message, log_new_case, log_start_test_code, log_end_test_code, log_request_response_to_file

# Logging
REQUESTLOGGER = logging.getLogger('log_all_requests_of_testcases_to_file')
REQUESTLOGGER.addHandler(b2handle.util.NullHandler())

# Load some data that is needed for testing
PATH_RES = b2handle.util.get_neighbour_directory(__file__, 'resources')
RESOURCES_FILE = json.load(open(PATH_RES+'/testvalues_for_integration_tests_IGNORE.json'))
# This file is not public, as it contains valid credentials for server
# write access. However, by providing such a file, you can run the tests.
# A template can be found in resources/testvalues_for_integration_tests_template.json


class EUDATHandleClientWriteaccess10320LOCTestCase(unittest.TestCase):

    def __init__(self, *args, **kwargs):

        REQUESTLOGGER.info("\nINIT of EUDATHandleClientWriteaccess10320LOCTestCase")

        unittest.TestCase.__init__(self, *args, **kwargs)

        # Read resources from file:
        self.testvalues = RESOURCES_FILE

        # Test values that need to be given by user:
        self.url = self.testvalues['handle_server_url_write']
        self.user = self.testvalues['user']
        self.password = self.testvalues['password']
        self.handle = self.testvalues['handle_for_read_tests']
        self.handle_withloc = self.testvalues['handle_to_be_modified_with_10320LOC']
        self.handle_withoutloc = self.testvalues['handle_to_be_modified_without_10320LOC']

        # Optional:
        self.https_verify = True
        if 'HTTPS_verify' in self.testvalues:
            self.https_verify = self.testvalues['HTTPS_verify']

        # Others
        self.randompassword = 'some_random_password_shrgfgh345345'
        prefix = self.handle.split('/')[0]
        self.inexistent_handle = prefix+'/07e1fbf3-2b72-430a-a035-8584d4eada41'
        self.headers = None
        self.connector = HandleSystemConnector(handle_server_url = self.url)

    def setUp(self):

        REQUESTLOGGER.info("\n"+60*"*"+"\nsetUp of EUDATHandleClientWriteaccess10320LOCTestCase")

        self.inst = EUDATHandleClient.instantiate_with_username_and_password(
            self.url,
            self.user,
            self.password,
            HTTPS_verify=self.https_verify)
        
        list_of_all_entries_with = [
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
                "index":1,
                "type":"URL",
                "data":"www.url.foo"
            },
            {
                "index":2,
                "type":"10320/LOC",
                "data":{
                    "format":"string",
                    "value":"<locations><location href = 'http://first.foo' /><location href = 'http://second.foo' /></locations> "
                }
            }
        ]

        list_of_all_entries_without = [
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
                "index":1,
                "type":"URL",
                "data":"www.url.foo"
            }
        ]

        authstring = b2handle.utilhandle.create_authentication_string(self.user, self.password)
        head = {
            'Content-Type': 'application/json',
            'Authorization': 'Basic '+authstring
        }
        veri = self.https_verify

        testhandle = self.handle_withloc
        url = self.connector.make_handle_URL(testhandle)
        data = json.dumps({'values':list_of_all_entries_with})
        resp = requests.put(url, data=data, headers=head, verify=veri)
        log_request_response_to_file('PUT', testhandle, url, head, veri, resp)

        testhandle = self.handle_withoutloc
        url = self.connector.make_handle_URL(testhandle)
        data = json.dumps({'values':list_of_all_entries_without})
        requests.put(url, data=data, headers=head, verify=veri)
        log_request_response_to_file('PUT', testhandle, url, head, veri, resp)

    def tearDown(self):

        veri = self.https_verify
        authstring = b2handle.utilhandle.create_authentication_string(self.user, self.password)
        head = {
            'Content-Type': 'application/json',
            'Authorization': 'Basic '+authstring
        }

        testhandle = self.handle_withloc
        url = self.connector.make_handle_URL(testhandle)
        resp = requests.delete(url, headers=head, verify=veri)
        log_request_response_to_file('DELETE', testhandle, url, head, veri, resp)

        testhandle = self.handle_withoutloc
        url = self.connector.make_handle_URL(testhandle)
        requests.delete(url, headers=head, verify=veri)
        log_request_response_to_file('DELETE', testhandle, url, head, veri, resp)

    # Exchanging:

    def test_exchange_additional_URL_normal(self):
        """Test replacing an URL."""
        log_new_case("test_exchange_additional_URL_normal")

        # Test variables
        testhandle = self.handle_withloc
        old = 'http://first.foo'
        new = 'http://newfirst.foo'

        # Precondition: URL must be included.
        handlerecord_json = self.inst.retrieve_handle_record_json(testhandle)
        contained = self.inst.is_URL_contained_in_10320LOC(testhandle, old, handlerecord_json)
        self.assertTrue(contained,
            'Precondition for test failed! The URL should be present at the start'
            ' of the test: '+str(handlerecord_json))

        # Run the code to be tested:
        log_start_test_code()
        self.inst.exchange_additional_URL(testhandle, old, new)
        log_end_test_code()

        # Check desired effects on handle:
        contained = self.inst.is_URL_contained_in_10320LOC(testhandle, new)
        self.assertTrue(contained,
            'After replacing an URL, the replacement was not there.')
        # TODO Check if index was the same!!

    def test_exchange_additional_URL_doesnotexist(self):
        """Test if replacing an inexistent URL has any effect."""
        log_new_case("test_exchange_additional_URL_doesnotexist")

        # Test variables
        testhandle = self.handle_withloc
        inexistent_old = 'http://sodohfasdkfjhanwikfhbawkedfhbawe.foo'
        new = 'http://newfirst.foo'

        # Precondition: URL must not be there yet.
        contained = self.inst.is_URL_contained_in_10320LOC(testhandle, inexistent_old)
        self.assertFalse(contained,
            'Precondition for test failed! The URL should not be present at the start of the test.')

        # Run the code to be tested:
        log_start_test_code()
        self.inst.exchange_additional_URL(testhandle, inexistent_old, new)
        log_end_test_code()

        # Check desired effects on handle:
        contained = self.inst.is_URL_contained_in_10320LOC(testhandle, new)
        self.assertFalse(contained,
            'After replacing a nonexistent URL, the replacement was there.')

    def test_exchange_additional_URL_no10320LOC(self):
        """Test if replacing an URL has any effect if there is no 10320/LOC."""
        log_new_case("test_exchange_additional_URL_no10320LOC")

        # Test variables
        testhandle = self.handle_withoutloc
        old = 'http://first.foo'
        new = 'http://newfirst.foo'

        # Run the code to be tested:
        log_start_test_code()
        self.inst.exchange_additional_URL(testhandle, old, new)
        log_end_test_code()

        # Check desired effects on handle:
        contained = self.inst.is_URL_contained_in_10320LOC(testhandle, new)
        self.assertFalse(contained,
            'After replacing an URL in nonexistent 10320/LOC, the replacement was there.')
    
    # Adding:

    def test_add_additional_URL_first(self):
        """Test adding the first additional URL'(created the 10320/LOC entry)."""
        log_new_case("test_add_additional_URL_first")

        # Test variables
        testhandle = self.handle_withoutloc
        url = 'http://first.foo'

        # Run code to be tested:
        log_start_test_code()
        self.inst.add_additional_URL(testhandle, url)
        log_end_test_code()

        # Check desired effects on handle:
        contained = self.inst.is_URL_contained_in_10320LOC(testhandle, url)
        self.assertTrue(contained,
            'The (first) URL was not added or the 10320/LOC was not created.')

    def test_add_additional_URL_several_toempty(self):
        """Test adding several (3) additional URLs."""
        log_new_case("test_add_additional_URL_several_toempty")

        # Test variables
        testhandle = self.handle_withoutloc
        url1 = 'http://one'
        url2 = 'http://two'
        url3 = 'http://three'

        # Run code to be tested:
        log_start_test_code()
        self.inst.add_additional_URL(testhandle, url1, url2, url3)
        log_end_test_code()

        # Check desired effects on handle:
        contained1 = self.inst.is_URL_contained_in_10320LOC(testhandle, url1)
        contained2 = self.inst.is_URL_contained_in_10320LOC(testhandle, url2)
        contained3 = self.inst.is_URL_contained_in_10320LOC(testhandle, url3)
        self.assertTrue(contained1,
            'The first added URL was not added.')
        self.assertTrue(contained2,
            'The second added URL was not added.')
        self.assertTrue(contained3,
            'The third added URL was not added.')

    def test_add_additional_URL_another(self):
        """Test adding an additional URL."""
        log_new_case("test_add_additional_URL_another")

        # Test variables:
        testhandle = self.handle_withloc
        url = 'http://third.foo'
        
        # Run code to be tested:
        log_start_test_code()
        self.inst.add_additional_URL(testhandle, url)
        log_end_test_code()

        # Check desired effects on handle:
        contained = self.inst.is_URL_contained_in_10320LOC(testhandle, url)
        self.assertTrue(contained,
            'The URL was not added.')

    def test_add_additional_URL_several(self):
        """Test adding several (3) additional URLs."""
        log_new_case("test_add_additional_URL_several")

        # Test variables
        testhandle = self.handle_withloc
        url1 = 'http://one'
        url2 = 'http://two'
        url3 = 'http://three'
        
        # Run code to be tested:
        log_start_test_code()
        self.inst.add_additional_URL(testhandle, url1, url2, url3)
        log_end_test_code()

        # Check desired effects on handle:
        contained1 = self.inst.is_URL_contained_in_10320LOC(testhandle, url1)
        contained2 = self.inst.is_URL_contained_in_10320LOC(testhandle, url2)
        contained3 = self.inst.is_URL_contained_in_10320LOC(testhandle, url3)
        self.assertTrue(contained1,
            'The first added URL was not added.')
        self.assertTrue(contained2,
            'The second added URL was not added.')
        self.assertTrue(contained3,
            'The third added URL was not added.')

    def test_add_additional_URL_to_inexistent_handle(self):
        """Test exception if handle does not exist."""
        log_new_case("test_add_additional_URL_to_inexistent_handle")

        # Test variables
        testhandle = self.inexistent_handle
        url = 'http://foo.foo'

        # Run code to be tested + check exception:
        log_start_test_code()
        with self.assertRaises(HandleNotFoundException):
            self.inst.add_additional_URL(testhandle, url)
        log_end_test_code()

    def test_add_additional_URL_alreadythere(self):
        """Test adding an URL that is already there."""
        log_new_case("test_add_additional_URL_alreadythere")

        # Test variables
        testhandle = self.handle_withloc
        url = 'http://first.foo'

        # Precondition: URL is already contained:
        record_before = self.inst.retrieve_handle_record_json(testhandle)
        contained = self.inst.is_URL_contained_in_10320LOC(testhandle, url, record_before)
        self.assertTrue(contained,
            'Test precondition failed: URL not there: '+str(record_before))

        # Run code to be tested:
        log_start_test_code()
        self.inst.add_additional_URL(testhandle, url)
        log_end_test_code()

        # Check desired effects on handle:
        # i.e. check if something has changed
        record_after  = self.inst.retrieve_handle_record_json(testhandle)
        self.assertEqual(record_before, record_after,
                        'After adding the same URL again, '
                        'the record was not equal.\n'
                        'Before:\n'+str(record_before)+'\n'
                        'After:\n'+str(record_after))

    # Remove:

    def test_remove_additional_URL(self):
        """Test normal removal of additional URL from 10320/LOC."""
        log_new_case("test_remove_additional_URL")

        # Test variables
        testhandle = self.handle_withloc
        url = 'http://first.foo'

        # Run code to be tested:
        log_start_test_code()
        self.inst.remove_additional_URL(testhandle, url)
        log_end_test_code()

        # Check desired effects on handle:
        contained = self.inst.is_URL_contained_in_10320LOC(testhandle, url)
        self.assertFalse(contained,
            'After removal, the URL was still there.')

    def test_remove_additional_URL_toempty(self):
        """Test removing all URL, which should remove the whole 10320/LOC attribute."""
        log_new_case("test_remove_additional_URL_toempty")

        # Test variables
        testhandle = self.handle_withloc
        url1 =  'http://first.foo'
        url2 = 'http://second.foo'

        # Run code to be tested:
        log_start_test_code()
        self.inst.remove_additional_URL(testhandle, url1)
        self.inst.remove_additional_URL(testhandle, url2)
        log_end_test_code()

        # Check desired effects on handle:
        # Check if empty:
        isempty = self.inst.is_10320LOC_empty(testhandle)
        self.assertTrue(isempty,
            'After removing all URLs from 10320/LOC, it is not empty.')
        # Check if still exists:
        rec = self.inst.retrieve_handle_record_json(testhandle)
        val = self.inst.get_value_from_handle(testhandle, '10320/LOC', rec)
        indices = self.inst.get_handlerecord_indices_for_key('10320/LOC', rec['values'])
        self.assertIsNone(val,
            'After removing all URLs from 10320/LOC, the value is not None.')
        self.assertEqual(len(indices), 0,
            'After removing all URLs from 10320/LOC, the entry still exists.')


    def test_remove_additional_URL_several(self):
        """Test removing all URL at the same time, which should remove the whole 10320/LOC attribute."""
        log_new_case("test_remove_additional_URL_several")

        # Test variables
        testhandle = self.handle_withloc
        url1 =  'http://first.foo'
        url2 = 'http://second.foo'

        # Run code to be tested:
        log_start_test_code()
        self.inst.remove_additional_URL(testhandle, url1, url2)
        log_end_test_code()

        # Check desired effects on handle:
        # Check if empty:
        isempty = self.inst.is_10320LOC_empty(testhandle)
        self.assertTrue(isempty,
            'After removing all URLs from 10320/LOC, it is not empty.')
        # Check if still exists:
        rec = self.inst.retrieve_handle_record_json(testhandle)
        val = self.inst.get_value_from_handle(testhandle, '10320/LOC', rec)
        indices = self.inst.get_handlerecord_indices_for_key('10320/LOC', rec['values'])
        self.assertIsNone(val,
            'After removing all URLs from 10320/LOC, the value is not None.')
        self.assertEqual(len(indices), 0,
            'After removing all URLs from 10320/LOC, the entry still exists.')

    def test_remove_additional_URL_inexistent_handle(self):
        """Test normal removal of additional URL from an inexistent handle."""
        log_new_case("test_remove_additional_URL_inexistent_handle")

        # Test variables
        testhandle = self.inexistent_handle
        url = 'http://first.foo'

        # Run code to be tested + check exception:
        log_start_test_code()
        with self.assertRaises(HandleNotFoundException):
            self.inst.remove_additional_URL(testhandle, url)
        log_end_test_code()
