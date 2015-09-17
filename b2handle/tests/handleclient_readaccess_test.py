"""Testing methods that need Handle server read access"""

import unittest
import requests
import json
import sys
sys.path.append("../..")
import b2handle.clientcredentials
from b2handle.handleclient import EUDATHandleClient
from b2handle.handleexceptions import HandleSyntaxError
from b2handle.handleexceptions import HandleNotFoundException
from b2handle.handleexceptions import GenericHandleError
from b2handle.handleexceptions import HandleAlreadyExistsException
from b2handle.handleexceptions import BrokenHandleRecordException
from b2handle.handleexceptions import ReverseLookupException

RESOURCES_FILE = 'resources/testvalues_for_integration_tests_IGNORE.json'

class EUDATHandleClientReadaccessTestCase(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        unittest.TestCase.__init__(self, *args, **kwargs)
        self.testvalues = json.load(open(RESOURCES_FILE))
        self.handle = self.testvalues['handle_to_be_modified']
        self.inexistent_handle = self.testvalues['handle_doesnotexist']
        self.url_https = self.testvalues['url_https']
        self.user = self.testvalues['user']
        self.user_no_index = self.testvalues['user_without_index']
        self.inexistent_user = self.testvalues['nonexistent_user']
        self.handle_withloc = self.testvalues['handle_with_10320loc']
        self.handle_withoutloc = self.testvalues['handle_without_10320loc']
        self.verify = self.testvalues['HTTP_verify']
        self.randompassword = 'some_random_password_shrgfgh345345'

    # TODO More tests for constructors!

    def setUp(self):
        self.inst = EUDATHandleClient(HTTP_verify=self.verify)

    def tearDown(self):
        pass

    def test_retrieve_handle_record_json(self):
        """Test reading handle record from server."""
        rec = self.inst.retrieve_handle_record_json(self.handle)
        self.assertEqual(rec['values'][2]['type'], 'test3',
            'The type should be "test3".')
        self.assertEqual(rec['values'][2]['data']['value'], 'val3',
            'The value should be "val3".')

    def test_get_value_from_handle_normal(self):
        """Test reading existent and inexistent handle value from server."""
        val = self.inst.get_value_from_handle(self.handle, 'test1')
        self.assertEqual(val, 'val1',
            'Retrieving "test1" should lead to "val1", but it lead to: '+str(val))

    def test_get_value_from_handle_inexistent_key(self):
        val = self.inst.get_value_from_handle(self.handle, 'test100')
        self.assertIsNone(val,
            'Retrieving "test100" should lead to "None", but it lead to: '+str(val))

    def test_get_value_from_handle_inexistent_record(self):
        """Test reading handle value from inexistent handle."""
        with self.assertRaises(HandleNotFoundException):
            _val = self.inst.get_value_from_handle(self.inexistent_handle, 'anykey')

    def test_instantiate_with_username_and_wrong_password(self):
        """Test instantiation of client: No exception if password wrong."""
        EUDATHandleClient.instantiate_with_username_and_password(
            self.url_https,
            self.user,
            self.randompassword,
            HTTP_verify=self.verify)
        
    def test_instantiate_with_username_without_index_and_password(self):
        """Test instantiation of client: Exception if username has no index."""
        with self.assertRaises(HandleSyntaxError):
            EUDATHandleClient.instantiate_with_username_and_password(
                self.url_https,
                self.user_no_index,
                self.randompassword,
                HTTP_verify=self.verify)

    def test_instantiate_with_nonexistent_username_and_password(self):
        """Test instantiation of client: Exception if username does not exist."""
        with self.assertRaises(HandleNotFoundException):
            EUDATHandleClient.instantiate_with_username_and_password(
                self.url_https,
                self.inexistent_user,
                self.randompassword,
                HTTP_verify=self.verify)

    def test_instantiate_with_credentials(self):
        """Test instantiation of client: No exception if password wrong."""
        credentials = b2handle.clientcredentials.PIDClientCredentials(
            self.url_https,
            self.user,
            self.randompassword)
        EUDATHandleClient.instantiate_with_credentials(
            credentials,
            HTTP_verify=self.verify)

    def test_instantiate_with_credentials(self):
        """Test instantiation of client: Exception if username does not exist."""
        credentials = b2handle.clientcredentials.PIDClientCredentials(
            self.url_https,
            self.inexistent_user,
            self.randompassword)

        with self.assertRaises(HandleNotFoundException):
            EUDATHandleClient.instantiate_with_credentials(credentials,
                HTTP_verify=self.verify)

        # If the user name has no index, exception is already thrown in credentials creation!
        #self.assertRaises(HandleSyntaxError, b2handle.PIDClientCredentials, 'url', 'prefix/suffix', randompassword)
