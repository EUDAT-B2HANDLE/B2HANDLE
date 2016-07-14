"""Testing methods that need Handle server read access"""

import unittest
import requests
import json
import logging
import sys
from mock import MagicMock
sys.path.append("../..")
import b2handle.clientcredentials
from b2handle.handleclient import EUDATHandleClient
from b2handle.handleexceptions import HandleSyntaxError
from b2handle.handleexceptions import HandleNotFoundException
from b2handle.handleexceptions import GenericHandleError
from b2handle.handleexceptions import HandleAlreadyExistsException
from b2handle.handleexceptions import BrokenHandleRecordException
from b2handle.handleexceptions import ReverseLookupException
import b2handle.tests.utilities as utils

PATH_RES = utils.get_neighbour_directory(__file__, 'resources')
RESOURCES_FILE = PATH_RES+'/testvalues_for_integration_tests_IGNORE.json'

class NullHandler(logging.Handler):
    def emit(self, record):
        pass

LOGGER = logging.getLogger(__name__)
LOGGER.addHandler(NullHandler())

class EUDATHandleClientReadaccessTestCase(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        unittest.TestCase.__init__(self, *args, **kwargs)

        # Read resources from file:
        self.testvalues = json.load(open(RESOURCES_FILE))

        # Test values that need to be given by user:
        self.handle = self.testvalues['handle_for_read_tests']
        self.handle_global = self.testvalues['handle_globally_resolvable']
        self.user = self.testvalues['user']

        # Optional:
        self.https_verify = True
        if 'HTTPS_verify' in self.testvalues:
            self.https_verify = self.testvalues['HTTPS_verify']
        self.url = 'http://hdl.handle.net'
        if 'handle_server_url_read' in self.testvalues.keys():
            self.url = self.testvalues['handle_server_url_read']
        self.path_to_api = None
        if 'url_extension_REST_API' in self.testvalues.keys():
            self.path_to_api = self.testvalues['url_extension_REST_API']

        # Others
        prefix = self.handle.split('/')[0]
        self.inexistent_handle = prefix+'/07e1fbf3-2b72-430a-a035-8584d4eada41'
        self.randompassword = 'some_random_password_shrgfgh345345'

    def setUp(self):
        """ For most test, provide a client instance with the user-specified
        handle server url."""

        self.inst = EUDATHandleClient(
            HTTPS_verify=self.https_verify,
            handle_server_url=self.url,
            url_extension_REST_API=self.path_to_api)

        # Before being able to run these tests without write access,
        # the handle that we use for testing must exist. With this code,
        # you can create it. You only need to create it once and leave it
        # on the server, it will not be modified and can be used eternally.
        if False:
            # This should always be false!!! Except for creating the
            # required handle once! 
            self.create_required_test_handles()

    def tearDown(self):
        pass
        pass

    def create_required_test_handles(self):

        # Creating an instance that knows how to write:
        pw = self.testvalues['password']
        inst = EUDATHandleClient.instantiate_with_username_and_password(
            self.testvalues['handle_server_url_write'],
            self.user,
            pw,
            HTTPS_verify=self.https_verify)

        authstring = self.inst.create_authentication_string(self.user, pw)
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Basic '+authstring
        }

        list_of_all_entries = [
            {
                "index":111,
                "type":"TEST1",
                "data":"val1"
            },
            {
                "index":2222,
                "type":"TEST2",
                "data":"val2"
            },
            {
                "index":333,
                "type":"TEST3",
                "data":"val3"
            },
            {
                "index":4,
                "type":"TEST4",
                "data":"val4"
            }
        ]

        testhandle = self.handle
        url = inst.make_handle_URL(testhandle)
        veri = self.https_verify
        head = headers
        data = json.dumps({'values':list_of_all_entries})
        resp = requests.put(url, data=data, headers=head, verify=veri)


    # retrieve_handle_record_json

    def test_retrieve_handle_record_json(self):
        """Test reading handle record from server."""

        rec = self.inst.retrieve_handle_record_json(self.handle)

        self.assertEqual(rec['values'][2]['type'], 'test3',
            'The type should be "test3".')
        self.assertEqual(rec['values'][2]['data']['value'], 'val3',
            'The value should be "val3".')

    # get_value_from_handle

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
            val = self.inst.get_value_from_handle(self.inexistent_handle, 'anykey')

    # instantiate

    def test_instantiate_with_username_and_wrong_password(self):
        """Test instantiation of client: No exception if password wrong."""

        # Create client instance with username and password
        inst = EUDATHandleClient.instantiate_with_username_and_password(
            self.url,
            self.user,
            self.randompassword,
            HTTPS_verify=self.https_verify)
        self.assertIsInstance(inst, EUDATHandleClient)
        
    def test_instantiate_with_username_without_index_and_password(self):
        """Test instantiation of client: Exception if username has no index."""
        testusername_without_index = self.user.split(':')[1]

        # Run code to be tested + check exception:
        with self.assertRaises(HandleSyntaxError):

            # Create client instance with username and password
            inst = EUDATHandleClient.instantiate_with_username_and_password(
                self.url,
                testusername_without_index,
                self.randompassword,
                HTTPS_verify=self.https_verify)

    def test_instantiate_with_nonexistent_username_and_password(self):
        """Test instantiation of client: Exception if username does not exist."""
        testusername_inexistent = '100:'+self.inexistent_handle

        # Run code to be tested + check exception:
        with self.assertRaises(HandleNotFoundException):

            # Create client instance with username and password
            inst = EUDATHandleClient.instantiate_with_username_and_password(
                self.url,
                testusername_inexistent,
                self.randompassword,
                HTTPS_verify=self.https_verify)

    def test_instantiate_with_credentials(self):
        """Test instantiation of client: No exception if password wrong."""

        # Test variables
        credentials = b2handle.clientcredentials.PIDClientCredentials(
            handle_server_url=self.url,
            username=self.user,
            password=self.randompassword)

        # Run code to be tested
        # Create instance with credentials
        inst = EUDATHandleClient.instantiate_with_credentials(
            credentials,
            HTTPS_verify=self.https_verify)

        # Check desired outcomes
        self.assertIsInstance(inst, EUDATHandleClient)

    def test_instantiate_with_credentials_inexistentuser(self):
        """Test instantiation of client: Exception if username does not exist."""

        # Test variables
        testusername_inexistent = '100:'+self.inexistent_handle
        credentials = b2handle.clientcredentials.PIDClientCredentials(
            handle_server_url=self.url,
            username=testusername_inexistent,
            password=self.randompassword)

        # Run code to be tested + check exception:
        # Create instance with credentials
        with self.assertRaises(HandleNotFoundException):
            inst = EUDATHandleClient.instantiate_with_credentials(credentials,
                HTTPS_verify=self.https_verify)

        # If the user name has no index, exception is already thrown in credentials creation!
        #self.assertRaises(HandleSyntaxError, b2handle.PIDClientCredentials, 'url', 'prefix/suffix', randompassword)

    def test_instantiate_with_credentials_config_override(self):
        """Test instantiation of client: No exception if password wrong."""

        # Test variables
        credentials = MagicMock()
        config_from_cred = {}
        valuefoo = 'foo/foo/foo/'
        config_from_cred['REST_API_url_extension'] = valuefoo
        credentials.get_config = MagicMock(return_value=config_from_cred)
        credentials.get_username = MagicMock(return_value=self.user)
        credentials.get_password = MagicMock(return_value=self.randompassword)
        credentials.get_server_URL = MagicMock(return_value=self.url)
        credentials.get_path_to_private_key = MagicMock(return_value=None)
        credentials.get_path_to_file_certificate_only = MagicMock(return_value=None)
        credentials.get_path_to_file_certificate_and_key = MagicMock(return_value=None)

        self.assertEqual(credentials.get_config()['REST_API_url_extension'],valuefoo,
            'Config: '+str(credentials.get_config()))

        # Run code to be tested
        # Create instance with credentials
        inst = EUDATHandleClient.instantiate_with_credentials(
            credentials,
            HTTPS_verify=self.https_verify,
            REST_API_url_extension='api/handles')

        # If this raises an exception, it is because /foo/foo from the
        # credentials config was used as path. /foo/foo should be overridden
        # by the standard stuff.

        # Check desired outcomes
        self.assertIsInstance(inst, EUDATHandleClient)
        val = self.inst.get_value_from_handle(self.handle, 'test1')
        self.assertEqual(val, 'val1',
            'Retrieving "test1" should lead to "val1", but it lead to: '+str(val))

    def test_instantiate_with_credentials_config(self):
        """Test instantiation of client: No exception if password wrong."""

        # Test variables
        credentials = MagicMock()
        config_from_cred = {}
        valuefoo = 'foo/foo/foo/'
        config_from_cred['REST_API_url_extension'] = valuefoo
        credentials.get_config = MagicMock(return_value=config_from_cred)
        credentials.get_username = MagicMock(return_value=self.user)
        credentials.get_password = MagicMock(return_value=self.randompassword)
        credentials.get_server_URL = MagicMock(return_value=self.url)
        credentials.get_handleowner = MagicMock(return_value=None)
        credentials.get_path_to_private_key = MagicMock(return_value=None)
        credentials.get_path_to_file_certificate_only = MagicMock(return_value=None)
        credentials.get_path_to_file_certificate_and_key = MagicMock(return_value=None)

        self.assertEqual(credentials.get_config()['REST_API_url_extension'],valuefoo,
            'Config: '+str(credentials.get_config()))

        # Run code to be tested
        # Create instance with credentials
        with self.assertRaises(GenericHandleError):
            inst = EUDATHandleClient.instantiate_with_credentials(
                credentials,
                HTTPS_verify=self.https_verify)

        # If this raises an exception, it is because /foo/foo from the
        # credentials config was used as path. /foo/foo should be overridden
        # by the standard stuff.

    def test_global_resolve(self):
        """Testing if instantiating with default handle server'works
        and if a handle is correctly retrieved. """

        # Create instance with default server url:
        inst = EUDATHandleClient(HTTPS_verify=self.https_verify)
        rec = inst.retrieve_handle_record_json(self.handle_global)

        self.assertIn('handle', rec,
            'Response lacks "handle".')
        self.assertIn('responseCode', rec,
            'Response lacks "responseCode".')

    def test_instantiate_for_read_access(self):
        """Testing if instantiating with default handle server works
        and if a handle is correctly retrieved. """

        # Create client instance with username and password
        inst = EUDATHandleClient.instantiate_for_read_access(HTTPS_verify=self.https_verify)
        rec = self.inst.retrieve_handle_record_json(self.handle)
        self.assertIsInstance(inst, EUDATHandleClient)
        self.assertIn('handle', rec,
            'Response lacks "handle".')
        self.assertIn('responseCode', rec,
            'Response lacks "responseCode".')