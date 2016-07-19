"""Testing methods that need Handle server write access"""


import sys
if sys.version_info < (2, 7):
    import unittest2 as unittest
else:
    import unittest

import logging
import requests
import json
import b2handle
from b2handle.handleclient import EUDATHandleClient
from b2handle.handleexceptions import *
from b2handle.tests.utilities import failure_message, log_new_case, log_start_test_code, log_end_test_code, log_request_response_to_file

REQUESTLOGGER = logging.getLogger('log_all_requests_of_testcases_to_file')
REQUESTLOGGER.addHandler(b2handle.util.NullHandler())

# Load some data that is needed for testing
PATH_RES = b2handle.util.get_neighbour_directory(__file__, 'resources')
RESOURCES_FILE = json.load(open(PATH_RES+'/testvalues_for_integration_tests_IGNORE.json'))
# This file is not public, as it contains valid credentials for server
# write access. However, by providing such a file, you can run the tests.
# A template can be found in resources/testvalues_for_integration_tests_template.json


class EUDATHandleClientSearchTestCase(unittest.TestCase):

    def __init__(self, *args, **kwargs):

        REQUESTLOGGER.info("\nINIT of EUDATHandleClientSearchTestCase")

        unittest.TestCase.__init__(self, *args, **kwargs)

        # Read resources from file:
        self.testvalues = RESOURCES_FILE

        # Test values that need to be given by user:
        self.searchuser = self.testvalues['reverselookup_username']
        self.searchpassword = self.testvalues['reverselookup_password']
        self.searchurl = self.testvalues['reverselookup_baseuri']
        self.searchurl_wrong = self.testvalues['reverselookup_baseuri_wrong']
        self.handle = self.testvalues['handle_for_read_tests']

        # Optional:
        self.url = None
        if 'handle_server_url_read' in self.testvalues.keys():
            self.url = self.testvalues['handle_server_url_read']
        self.https_verify = True
        if 'HTTPS_verify' in self.testvalues.keys():
            self.https_verify = self.testvalues['HTTPS_verify']
        self.searchpath = None
        if 'reverselookup_url_extension' in self.testvalues.keys():
            self.searchpath = self.testvalues['reverselookup_url_extension']
        self.path_to_api = None
        if 'url_extension_REST_API' in self.testvalues.keys():
            self.path_to_api = self.testvalues['url_extension_REST_API']

        # Others:
        self.randompassword = 'some_random_password_dghshsrtsrth'
        self.prefix_inexistent = '9999999999999999'
        self.url_inexistent = 'noturldoesnotexist'

    def setUp(self):
        '''Providing a client instance that has read and search access
        to the servers specified in the test resources JSON file.
        '''

        REQUESTLOGGER.info("\n"+60*"*"+"\nsetUp of EUDATHandleClientSearchTestCase")

        self.inst = EUDATHandleClient.instantiate_for_read_and_search(
            self.url,
            self.searchuser,
            self.searchpassword,
            reverselookup_baseuri=self.searchurl,
            reverselookup_url_extension=self.searchpath,
            HTTPS_verify=self.https_verify)

    def tearDown(self):
        pass
        pass

    def test_search_handle_wrong_url_test(self):
        """Test exception when wrong search servlet URL is given."""
        log_new_case("test_search_handle_wrong_url_test")

        # Make new client instance with existing but wrong url for searching:
        inst = EUDATHandleClient.instantiate_for_read_and_search(
            self.url,
            self.searchuser,
            self.searchpassword,
            reverselookup_baseuri=self.searchurl_wrong,
            reverselookup_url_extension=self.searchpath,
            HTTPS_verify=self.https_verify)

        # Run code to be tested + check exception:
        log_start_test_code()
        with self.assertRaises(ReverseLookupException):
            inst.search_handle(URL='*')
        log_end_test_code()

    def test_search_handle_hs_url_test(self):
        """Test exception when wrong search servlet URL (Handle Server REST API URL) is given."""
        log_new_case("test_search_handle_hs_url_test")

        # Make new instance with handle server url as search url:
        self.inst = EUDATHandleClient.instantiate_for_read_and_search(
            self.url,
            self.searchuser,
            self.searchpassword,
            reverselookup_baseuri=self.url,
            reverselookup_url_extension=self.path_to_api,
            HTTPS_verify=self.https_verify)

        # Run code to be tested + check exception:
        log_start_test_code()
        with self.assertRaises(ReverseLookupException):
            self.inst.search_handle(URL='*')
            # TODO specify exception
        log_end_test_code()

    if False: # Does not work, es the Search Servlet runs out of Heap Space. Too many entries.
        def test_search_handle(self):
            """Test searching for handles with any url (server should return list of handles)."""
            log_new_case("test_search_handle")

            log_start_test_code()
            val = self.inst.search_handle(URL='*')
            log_end_test_code()

            # Check desired outcome:
            self.assertEqual(type(val),type([]),
                'Searching did not return a list, but: '+str(val))
            self.assertTrue(len(val) > 0,
                'Searching did not return any handles!')
            self.assertTrue(self.inst.check_handle_syntax(val[0]),
                'Searching returned handles with a wrong syntax, e.g.: '+str(val[0]))

    def test_search_handle_emptylist(self):
        """Test empty search result."""
        log_new_case("test_search_handle_emptylist")

        log_start_test_code()
        val = self.inst.search_handle(URL=self.url_inexistent)
        log_end_test_code()

        # Check desired outcome:
        self.assertEqual(type(val),type([]),
            'Searching did not return a list, but: '+str(val)+', type: '+str(type(val)))
        self.assertEqual(len(val),0,
            'Searching did not return an empty list, but: '+str(val))

    def test_search_handle_for_url(self):
        """Test searching for url with wildcards."""
        log_new_case("test_search_handle_for_url")

        log_start_test_code()
        val1 = self.inst.search_handle(URL='*dkrz*')
        log_end_test_code()
        log_start_test_code()
        val2 = self.inst.search_handle('*dkrz*')
        log_end_test_code()

        # Check desired outcome:
        self.assertEqual(type(val1),type([]),
            'Searching did not return a list, but: '+str(val1)+', type: '+str(type(val1)))
        self.assertEqual(val1, val2,
            'Searching with or without keyword did not return the same result:'+\
            '\nwith keyword: '+str(val1)+'\nwithout: '+str(val2))

    def test_search_handle_for_url_and_checksum(self):
        """Test searching for url and checksum with wildcards."""
        log_new_case("test_search_handle_for_url_and_checksum")

        log_start_test_code()
        val1 = self.inst.search_handle('*dkrz*', CHECKSUM='*1111111111111*')

        log_end_test_code()
        log_start_test_code()
        val2 = self.inst.search_handle(URL='*dkrz*', CHECKSUM='*1111111111111*')
        log_end_test_code()

        # Check desired outcome:
        self.assertEqual(type(val1),type([]),
            'Searching did not return a list, but: '+str(val1)+', type: '+str(type(val1)))
        self.assertEqual(val1, val2,
            'Searching with or without keyword did not return the same result:'+\
            '\nwith keyword: '+str(val1)+'\nwithout: '+str(val2))
        self.assertEqual(val1, [], 'val1 is: '+str(val1)+', instead of []')
        self.assertEqual(val2, [], 'val2 is: '+str(val2)+', instead of []')

    def test_search_handle_for_checksum(self):
        """Test searching for checksum with wildcards."""
        log_new_case("test_search_handle_for_checksum")

        log_start_test_code()
        val1 = self.inst.search_handle(None, CHECKSUM='*1111111111111*')

        log_end_test_code()
        log_start_test_code()
        val2 = self.inst.search_handle(URL=None, CHECKSUM='*1111111111111*')
        log_end_test_code()

        # Check desired outcome:
        self.assertEqual(type(val1),type([]),
            'Searching did not return a list, but: '+str(val1)+', type: '+str(type(val1)))
        self.assertEqual(val1, val2,
            'Searching with or without keyword did not return the same result:'+\
            '\nwith keyword: '+str(val1)+'\nwithout: '+str(val2))
        self.assertEqual(val1, [], 'val1 is: '+str(val1)+', instead of []')
        self.assertEqual(val2, [], 'val2 is: '+str(val2)+', instead of []')

    def test_search_handle_prefixfilter(self):
        """Test filtering for prefixes."""
        log_new_case("test_search_handle_prefixfilter")

        prefix1 = self.prefix_inexistent
        prefix2 = self.handle.split('/')[0]

        log_start_test_code()
        val1 = self.inst.search_handle(URL='*dkrz*', prefix=prefix1)
        log_end_test_code()
        log_start_test_code()
        val2 = self.inst.search_handle(URL='*dkrz*', prefix=prefix2)
        log_end_test_code()

        # Check desired outcome:
        self.assertEqual(type(val1),type([]),
            'Searching did not return a list, but: '+str(val1)+', type: '+str(type(val1)))
        for item in val1:
            self.assertEqual(item.split('/')[0], prefix1,
                'This search result has the wrong prefix: '+item+', should be '+prefix1)

        self.assertEqual(type(val2),type([]),
            'Searching did not return a list, but: '+str(val1)+', type: '+str(type(val1)))
        for item in val2:
            self.assertEqual(item.split('/')[0], prefix2,
                'This search result has the wrong prefix: '+item+', should be '+prefix2)
