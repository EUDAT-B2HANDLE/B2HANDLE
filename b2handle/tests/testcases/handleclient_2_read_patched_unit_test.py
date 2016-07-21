"""Testing methods that normally need Handle server read access,
by patching the get request to replace read access."""

import sys
if sys.version_info < (2, 7):
    import unittest2 as unittest
else:
    import unittest

import mock
import json
import b2handle
from b2handle.handleclient import EUDATHandleClient
from b2handle.handleexceptions import HandleSyntaxError, GenericHandleError, HandleNotFoundException
from b2handle.tests.mockresponses import MockResponse, MockSearchResponse, MockCredentials

# Load some data that is needed for testing
PATH_RES = b2handle.util.get_neighbour_directory(__file__, 'resources')
RECORD = open(PATH_RES+'/handlerecord_for_reading_PUBLIC.json').read()

class EUDATHandleClientReadaccessPatchedTestCase(unittest.TestCase):
    '''Testing methods that read the 10320/loc entry.'''

    def setUp(self):
        self.inst = EUDATHandleClient()

    def tearDown(self):
        pass

    # retrieve_handle_record_json:

    @mock.patch('b2handle.handleclient.requests.Session.get')
    def test_retrieve_handle_record_json_normal(self, getpatch):
        """Test if retrieve_handle_record_json returns the correct things.."""

        # Test variables:
        handlerecord = RECORD
        expected = json.loads(handlerecord)

        # Define the replacement for the patched method:
        mock_response = MockResponse(success=True, content=handlerecord)
        getpatch.return_value = mock_response

        # Call method and check result:
        received = self.inst.retrieve_handle_record_json(expected['handle'])
        self.assertEqual(received, expected,
            'Unexpected return from handle retrieval.')

    @mock.patch('b2handle.handleclient.requests.Session.get')
    def test_retrieve_handle_record_json_handle_does_not_exist(self, getpatch):
        """Test return value (None) if handle does not exist (retrieve_handle_record_json)."""

        # Test variables:
        testhandle = 'dont/exist'

        # Define the replacement for the patched method:
        mock_response = MockResponse(notfound=True)
        getpatch.return_value = mock_response

        # Call method and check result:
        json_record = self.inst.retrieve_handle_record_json(testhandle)
        self.assertIsNone(json_record,
            'The return value should be None if the handle does not exist, not: '+str(json_record))

    @mock.patch('b2handle.handleclient.requests.Session.get')
    def test_retrieve_handle_record_json_handle_empty(self, getpatch):
        """Test return value if handle is empty (retrieve_handle_record_json)."""

        # Test variables:
        testhandle = 'dont/exist'

        # Define the replacement for the patched method:
        mock_response = MockResponse(empty=True)
        getpatch.return_value = mock_response

        # Call method and check result:
        json_record = self.inst.retrieve_handle_record_json(testhandle)
        self.assertEquals(json_record['responseCode'],200,
            'Unexpected return value: '+str(json_record))

    @mock.patch('b2handle.handleclient.requests.Session.get')
    def test_retrieve_handle_record_json_genericerror(self, getpatch):
        """Test exception if retrieve_handle_record_json returns a strange HTTP code."""

        # Test variables:
        testhandle = 'dont/exist'

        # Define the replacement for the patched method:
        mock_response = MockResponse(status_code=99999)
        getpatch.return_value = mock_response

        # Call method and check result:
        with self.assertRaises(GenericHandleError):
            json_record = self.inst.retrieve_handle_record_json(testhandle)

    # retrieve_handle_record:

    #@mock.patch('b2handle.handleclient.EUDATHandleClient._EUDATHandleClient__send_handle_get_request')
    @mock.patch('b2handle.handleclient.requests.Session.get')
    def test_retrieve_handle_record_when_json_not_given(self, getpatch):
        """Test retrieving a handle record"""

        # Test variables
        handlerecord_string = RECORD
        handlerecord_json = json.loads(handlerecord_string)
        testhandle = handlerecord_json['handle']
        
        # Define the replacement for the patched method:
        mock_response = MockResponse(success=True, content=handlerecord_string)
        getpatch.return_value = mock_response

        # Call method and check result:
        dict_record = self.inst.retrieve_handle_record(testhandle)
        self.assertIn('TEST1', dict_record,
            'Key "test1" not in handlerecord dictionary!')
        self.assertIn('TEST2', dict_record,
            'Key "test2" not in handlerecord dictionary!')
        self.assertIn('TESTDUP', dict_record,
            'Key "TESTDUP" not in handlerecord dictionary!')
        self.assertIn('HS_ADMIN', dict_record,
            'Key "HS_ADMIN" not in handlerecord dictionary!')

        self.assertEqual(dict_record['TEST1'], 'val1',
            'The value of "test1" is not "val1.')
        self.assertEqual(dict_record['TEST2'], 'val2',
            'The value of "test2" is not "val2.')
        self.assertIn(dict_record['TESTDUP'], ("dup1", "dup2"),
            'The value of the duplicate key "TESTDUP" should be "dup1" or "dup2".')
        self.assertIn('permissions', dict_record['HS_ADMIN'],
            'The HS_ADMIN has no permissions: '+dict_record['HS_ADMIN'])

        self.assertEqual(len(dict_record), 4,
            'The record should have a length of 5 (as the duplicate is ignored.')

    @mock.patch('b2handle.handleclient.requests.Session.get')
    def test_retrieve_handle_record_when_handle_is_wrong(self, getpatch):
        """Test error when retrieving a handle record with contradicting inputs."""
        
        # Test variable
        testhandle = 'something/else'
        handlerecord_string = RECORD
        handlerecord_json = json.loads(handlerecord_string)

        # Define the replacement for the patched method:
        mock_response = MockResponse(success=True, content=handlerecord_string)
        getpatch.return_value = mock_response

        # Call method and check result:
        with self.assertRaises(GenericHandleError):
            self.inst.retrieve_handle_record(testhandle)

    @mock.patch('b2handle.handleclient.requests.Session.get')
    def test_retrieve_handle_record_when_handle_is_None(self, getpatch):
        """Test error when retrieving a handle record with a None input."""

        # Test variable
        testhandle = None

        # Call method and check result:
        with self.assertRaises(HandleSyntaxError):
            self.inst.retrieve_handle_record(testhandle)

    @mock.patch('b2handle.handleclient.requests.Session.get')
    def test_retrieve_handle_record_when_handle_is_wrong(self, getpatch):
        """Test error when retrieving a nonexistent handle record."""
        
        # Test variable
        testhandle = 'who/cares'

        # Define the replacement for the patched method:
        mock_response = MockResponse(notfound=True)
        getpatch.return_value = mock_response

        # Call method and check result:
        hrec = self.inst.retrieve_handle_record(testhandle)
        self.assertIsNone(hrec,
            'The handle record for a nonexistent handle should be None!')

    @mock.patch('b2handle.handleclient.requests.Session.get')
    def test_retrieve_handle_record_when_handlerecord_is_None(self, getpatch):
        """Test error when retrieving a handle record, giving a None type."""

        # Test variable
        handlerecord_string = RECORD
        handlerecord_json = json.loads(handlerecord_string)
        testhandle = handlerecord_json['handle']
        givenrecord = None

        # Define the replacement for the patched method:
        mock_response = MockResponse(success=True, content=handlerecord_string)
        getpatch.return_value = mock_response

        # Call method and check result:
        dict_record = self.inst.retrieve_handle_record(testhandle, givenrecord)
        self.assertIn('TEST1', dict_record,
            'Key "test1" not in handlerecord dictionary!')
        self.assertIn('TEST2', dict_record,
            'Key "test2" not in handlerecord dictionary!')
        self.assertIn('TESTDUP', dict_record,
            'Key "TESTDUP" not in handlerecord dictionary!')
        self.assertIn('HS_ADMIN', dict_record,
            'Key "HS_ADMIN" not in handlerecord dictionary!')

        self.assertEqual(dict_record['TEST1'], 'val1',
            'The value of "test1" is not "val1.')
        self.assertEqual(dict_record['TEST2'], 'val2',
            'The value of "test2" is not "val2.')
        self.assertIn(dict_record['TESTDUP'], ("dup1", "dup2"),
            'The value of the duplicate key "TESTDUP" should be "dup1" or "dup2".')
        self.assertIn('permissions', dict_record['HS_ADMIN'],
            'The HS_ADMIN has no permissions: '+dict_record['HS_ADMIN'])

        self.assertEqual(len(dict_record), 4,
            'The record should have a length of 5 (as the duplicate is ignored.')

    # get_value_from_handle

    @mock.patch('b2handle.handleclient.requests.Session.get')
    def test_get_value_from_handle_when_handle_inexistent(self, getpatch):
        """Test error when retrieving a handle record, giving a None type."""
        
        # Test variables
        testhandle = 'who/cares'
        key = 'foo'

        # Define the replacement for the patched method:
        mock_response = MockResponse(notfound=True)
        getpatch.return_value = mock_response

        # Call method and check result:
        with self.assertRaises(HandleNotFoundException):
            self.inst.get_value_from_handle(testhandle, key=key)

    @mock.patch('b2handle.handleclient.requests.Session.get')
    def test_is_10320LOC_empty_handle_does_not_exist(self, getpatch):
        """Test exception"""

        # Test variables
        testhandle = 'who/cares'

        # Define the replacement for the patched method:
        mock_response = MockResponse(notfound=True)
        getpatch.return_value = mock_response

        # Call method and check result:
        with self.assertRaises(HandleNotFoundException):
            self.inst.is_10320LOC_empty(testhandle)

    @mock.patch('b2handle.handleclient.requests.Session.get')
    def test_is_url_contained_in_10320LOC_handle_does_not_exist(self, getpatch):
        """Test exception"""

        # Test variables
        testhandle = 'who/cares'
        one_url = 'http://bla'
        list_of_urls = ['http://bla','http://foo.foo']

        # Define the replacement for the patched method:
        mock_response = MockResponse(notfound=True)
        getpatch.return_value = mock_response

        # Call method and check result:
        with self.assertRaises(HandleNotFoundException):
            self.inst.is_URL_contained_in_10320LOC(testhandle, url=one_url)
        with self.assertRaises(HandleNotFoundException):
            self.inst.is_URL_contained_in_10320LOC(testhandle, url=list_of_urls)

    # Instantiation

    @mock.patch('b2handle.handleclient.requests.Session.get')
    def test_instantiate_with_username_and_password_wrongpw(self, getpatch):
        

        # Define the replacement for the patched method:
        mock_response = MockResponse(success=True)
        getpatch.return_value = mock_response

        inst = EUDATHandleClient.instantiate_with_username_and_password(
                'http://someurl', '100:my/testhandle', 'passywordy')

        self.assertIsInstance(inst, EUDATHandleClient)

    @mock.patch('b2handle.handleclient.requests.Session.get')
    def test_instantiate_with_username_and_password_inexistentuser(self, getpatch):
        
        # Define the replacement for the patched method:
        mock_response = MockResponse(notfound=True)
        getpatch.return_value = mock_response

        with self.assertRaises(HandleNotFoundException):
            inst = EUDATHandleClient.instantiate_with_username_and_password(
                'http://someurl', '100:john/doe', 'passywordy')

    @mock.patch('b2handle.handleclient.requests.Session.get')
    def test_instantiate_with_credentials_inexistentuser(self, getpatch):
        """Test instantiation of client: Exception if username does not exist."""

        # Define the replacement for the patched method:
        mock_response = MockResponse(notfound=True)
        getpatch.return_value = mock_response

        # Test variables
        testusername_inexistent = '100:john/doe'
        credentials = b2handle.clientcredentials.PIDClientCredentials(
            handle_server_url='some/url',
            username=testusername_inexistent,
            password='some_password')

        # Run code to be tested + check exception:
        # Create instance with credentials
        with self.assertRaises(HandleNotFoundException):
            inst = EUDATHandleClient.instantiate_with_credentials(credentials)

        # If the user name has no index, exception is already thrown in credentials creation!
        #self.assertRaises(HandleSyntaxError, b2handle.PIDClientCredentials, 'url', 'prefix/suffix', randompassword)

    @mock.patch('b2handle.handleclient.requests.Session.get')
    def test_instantiate_with_credentials(self, getpatch):
        """Test instantiation of client: No exception if password wrong."""

        # Define the replacement for the patched method:
        mock_response = MockResponse(success=True)
        getpatch.return_value = mock_response

        # Test variables
        credentials = b2handle.clientcredentials.PIDClientCredentials(
            handle_server_url='some/url',
            username='100:my/testhandle',
            password='some_password_123')

        # Run code to be tested
        # Create instance with credentials
        inst = EUDATHandleClient.instantiate_with_credentials(credentials)

        # Check desired outcomes
        self.assertIsInstance(inst, EUDATHandleClient)

    @mock.patch('b2handle.handlesystemconnector.HandleSystemConnector.check_if_username_exists')
    def test_instantiate_with_credentials_config(self, checkpatch):
        """Test instantiation of client: No exception if password wrong."""

        # Define the replacement for the patched method:
        mock_response = MockResponse(success=True)
        checkpatch.return_value = mock_response

        # Test variables
        credentials = MockCredentials(restapi='foobar')

        self.assertEqual(credentials.get_config()['REST_API_url_extension'],'foobar',
            'Config: '+str(credentials.get_config()))

        # Run code to be tested
        # Create instance with credentials
        inst = EUDATHandleClient.instantiate_with_credentials(credentials)
        self.assertIsInstance(inst, EUDATHandleClient)

    @mock.patch('b2handle.handlesystemconnector.HandleSystemConnector.check_if_username_exists')
    @mock.patch('b2handle.handleclient.requests.Session.get')
    def test_instantiate_with_credentials_config_override(self, getpatch, checkpatch):
        """Test instantiation of client: We pass a config value in the credentials
        and also as an arg in the instantiation. We want the latter to override the
        first one.
        """

        # Define the replacement for the patched method:
        # We pretend the username exists!
        mock_response = MockResponse(success=True)
        checkpatch.return_value = mock_response

        # Define the replacement for the patched GET:
        cont = {"responseCode":1,"handle":"my/testhandle","values":[{"index":111,"type":"TEST1","data":{"format":"string","value":"val1"},"ttl":86400,"timestamp":"2015-09-30T15:08:49Z"},{"index":2222,"type":"TEST2","data":{"format":"string","value":"val2"},"ttl":86400,"timestamp":"2015-09-30T15:08:49Z"},{"index":333,"type":"TEST3","data":{"format":"string","value":"val3"},"ttl":86400,"timestamp":"2015-09-30T15:08:49Z"},{"index":4,"type":"TEST4","data":{"format":"string","value":"val4"},"ttl":86400,"timestamp":"2015-09-30T15:08:49Z"}]}
        mock_response = MockResponse(success=True, content=json.dumps(cont))
        getpatch.return_value = mock_response

        # Test variables
        # Passing mock credentials, give them the value "foobar", which
        # should be overridden!
        credentials = MockCredentials(restapi='foobar')
        self.assertEqual(credentials.get_config()['REST_API_url_extension'],'foobar',
            'Config: '+str(credentials.get_config()))

        # Run code to be tested
        # Create instance with credentials. It gets the "REST_API_url_extention"
        # from both the credentials and as a param.
        inst = EUDATHandleClient.instantiate_with_credentials(
            credentials,
            REST_API_url_extension='bar/bar/bar')
        self.assertIsInstance(inst, EUDATHandleClient)

        # How to know now which one was used?
        # Call a read and check its url! Did it get foobar or barbarbar appended?
        inst.get_value_from_handle('my/testhandle', 'key')
        positional_args_passed = getpatch.call_args_list[len(getpatch.call_args_list)-1][0]
        passed_url = positional_args_passed[0]

        # Compare with expected URL:
        self.assertIn('bar/bar/bar',passed_url,
            'bar/bar/bar is not specified in the URL '+passed_url)
