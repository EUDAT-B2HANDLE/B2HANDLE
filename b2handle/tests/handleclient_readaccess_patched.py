"""Testing methods that normally need Handle server read access,
by patching the get request to replace read access."""

import unittest
import mock
from mock import patch
import json
import sys
sys.path.append("../..")
from b2handle.handleclient import EUDATHandleClient
from b2handle.handleexceptions import HandleSyntaxError
from b2handle.handleexceptions import GenericHandleError
from b2handle.handleexceptions import HandleNotFoundException

class EUDATHandleClientReadaccessPatchedTestCase(unittest.TestCase):
    '''Testing methods that read the 10320/loc entry.'''

    def setUp(self):
        self.inst = EUDATHandleClient()


    def tearDown(self):
        pass

    # retrieve_handle_record_json:

    @patch('b2handle.handleclient.EUDATHandleClient._EUDATHandleClient__send_handle_get_request')
    def test_retrieve_handle_record_json_normal(self, methodkrams):
        """Test if retrieve_handle_record_json returns the correct things.."""

        # Define the replacement for the patched method:
        handlerecord = open('resources/handlerecord_for_reading.json').read()
        mock_response = MockResponse(success=True, content=handlerecord)
        methodkrams.return_value = mock_response

        expected = json.loads(handlerecord)


        # Call method and check result:
        json_record = self.inst.retrieve_handle_record_json(expected['handle'])
        self.assertEqual(json_record, expected,
            'Unexpected return from handle retrieval.')

    @patch('b2handle.handleclient.EUDATHandleClient._EUDATHandleClient__send_handle_get_request')
    def test_retrieve_handle_record_json_handle_does_not_exist(self, methodkrams):
        """Test return value (None) if handle does not exist (retrieve_handle_record_json)."""

        # Define the replacement for the patched method:
        mock_response = MockResponse(notfound=True)
        methodkrams.return_value = mock_response

        # Call method and check result:
        json_record = self.inst.retrieve_handle_record_json('test/handle')
        self.assertIsNone(json_record,
            'The return value should be None if the handle does not exist, not: '+str(json_record))

    @patch('b2handle.handleclient.EUDATHandleClient._EUDATHandleClient__send_handle_get_request')
    def test_retrieve_handle_record_json_handle_empty(self, methodkrams):
        """Test return value if handle is empty (retrieve_handle_record_json)."""

        # Define the replacement for the patched method:
        mock_response = MockResponse(empty=True)
        methodkrams.return_value = mock_response

        # Call method and check result:
        json_record = self.inst.retrieve_handle_record_json('test/handle')
        self.assertEquals(json_record['responseCode'],200,
            'Unexpected return value: '+str(json_record))

    @patch('b2handle.handleclient.EUDATHandleClient._EUDATHandleClient__send_handle_get_request')
    def test_retrieve_handle_record_json_genericerror(self, methodkrams):
        """Test exception if retrieve_handle_record_json returns a strange HTTP code."""

        # Define the replacement for the patched method:
        mock_response = MockResponse(status_code=99999)
        methodkrams.return_value = mock_response

        # Call method and check result:
        with self.assertRaises(GenericHandleError):
            json_record = self.inst.retrieve_handle_record_json('test/handle')

    # retrieve_handle_record:

    @patch('b2handle.handleclient.EUDATHandleClient._EUDATHandleClient__send_handle_get_request')
    def test_retrieve_handle_record_when_json_not_given(self, methodkrams):
        """Test retrieving a handle record"""
        
        # Define the replacement for the patched method:
        handlerecord_string = open('resources/handlerecord_for_reading.json').read()
        handlerecord_json = json.loads(handlerecord_string)
        mock_response = MockResponse(success=True, content=handlerecord_string)
        methodkrams.return_value = mock_response

        # Call method and check result:
        dict_record = self.inst.retrieve_handle_record(handlerecord_json['handle'])
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

    @patch('b2handle.handleclient.EUDATHandleClient._EUDATHandleClient__send_handle_get_request')
    def test_retrieve_handle_record_when_handle_is_wrong(self, methodkrams):
        """Test error when retrieving a handle record with contradicting inputs."""
        
        # Define the replacement for the patched method:
        handlerecord_string = open('resources/handlerecord_for_reading.json').read()
        handlerecord_json = json.loads(handlerecord_string)
        mock_response = MockResponse(success=True, content=handlerecord_string)
        methodkrams.return_value = mock_response

        # Call method and check result:
        with self.assertRaises(GenericHandleError):
            self.inst.retrieve_handle_record('something/else')

    @patch('b2handle.handleclient.EUDATHandleClient._EUDATHandleClient__send_handle_get_request')
    def test_retrieve_handle_record_when_handle_is_None(self, methodkrams):
        """Test error when retrieving a handle record with a None input."""

        # Call method and check result:
        with self.assertRaises(HandleSyntaxError):
            self.inst.retrieve_handle_record(None)

    @patch('b2handle.handleclient.EUDATHandleClient._EUDATHandleClient__send_handle_get_request')
    def test_retrieve_handle_record_when_handle_is_wrong(self, methodkrams):
        """Test error when retrieving a nonexistent handle record."""
        
        # Define the replacement for the patched method:
        mock_response = MockResponse(notfound=True)
        methodkrams.return_value = mock_response

        # Call method and check result:
        hrec = self.inst.retrieve_handle_record('who/cares')
        self.assertIsNone(hrec,
            'The handle record for a nonexistent handle should be None!')

    @patch('b2handle.handleclient.EUDATHandleClient._EUDATHandleClient__send_handle_get_request')
    def test_retrieve_handle_record_when_handlerecord_is_None(self, methodkrams):
        """Test error when retrieving a handle record, giving a None type."""
        
        # Define the replacement for the patched method:
        handlerecord_string = open('resources/handlerecord_for_reading.json').read()
        handlerecord_json = json.loads(handlerecord_string)
        mock_response = MockResponse(success=True, content=handlerecord_string)
        methodkrams.return_value = mock_response

        # Call method and check result:
        dict_record = self.inst.retrieve_handle_record(handlerecord_json['handle'], None)
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

    # get_value_from_handle

    @patch('b2handle.handleclient.EUDATHandleClient._EUDATHandleClient__send_handle_get_request')
    def test_get_value_from_handle_when_handle_inexistent(self, methodkrams):
        """Test error when retrieving a handle record, giving a None type."""
        
        # Define the replacement for the patched method:
        mock_response = MockResponse(notfound=True)
        methodkrams.return_value = mock_response

        # Call method and check result:
        with self.assertRaises(HandleNotFoundException):
            self.inst.get_value_from_handle('who/cares', key='bla')

    # check if username exists

    @patch('b2handle.handleclient.EUDATHandleClient._EUDATHandleClient__send_handle_get_request')
    def test_check_if_username_exists_normal(self, methodkrams):
        """Test whether username exists."""
        
        # Define the replacement for the patched method:
        handlerecord_string = open('resources/handlerecord_for_reading.json').read()
        handlerecord_json = json.loads(handlerecord_string)
        mock_response = MockResponse(success=True, content=handlerecord_string)
        methodkrams.return_value = mock_response

        # Call method and check result:
        res = self.inst.check_if_username_exists('100:'+handlerecord_json['handle'])
        self.assertTrue(res,
            'The handle exists, so "check_if_username_exists" should return true!')

    @patch('b2handle.handleclient.EUDATHandleClient._EUDATHandleClient__send_handle_get_request')
    def test_check_if_username_exists_inconsistent_info(self, methodkrams):
        """Test exception when contradictory inputs are given."""
        
        # Define the replacement for the patched method:
        handlerecord_string = open('resources/handlerecord_for_reading.json').read()
        handlerecord_json = json.loads(handlerecord_string)
        mock_response = MockResponse(success=True, content=handlerecord_string)
        methodkrams.return_value = mock_response

        # Call method and check result:
        with self.assertRaises(GenericHandleError):
            self.inst.check_if_username_exists('who/cares')

    @patch('b2handle.handleclient.EUDATHandleClient._EUDATHandleClient__send_handle_get_request')
    def test_check_if_username_exists_it_doesnot(self, methodkrams):
        """Test exception"""
        
        # Define the replacement for the patched method:
        mock_response = MockResponse(notfound=True)
        methodkrams.return_value = mock_response

        # Call method and check result:
        with self.assertRaises(HandleNotFoundException):
            self.inst.check_if_username_exists('who/cares')

    @patch('b2handle.handleclient.EUDATHandleClient._EUDATHandleClient__send_handle_get_request')
    def test_is_10320loc_empty_handle_does_not_exist(self, methodkrams):
        """Test exception"""

        # Define the replacement for the patched method:
        mock_response = MockResponse(notfound=True)
        methodkrams.return_value = mock_response

        # Call method and check result:
        with self.assertRaises(HandleNotFoundException):
            self.inst.is_10320loc_empty('who/cares')

    @patch('b2handle.handleclient.EUDATHandleClient._EUDATHandleClient__send_handle_get_request')
    def test_is_url_contained_in_10320loc_handle_does_not_exist(self, methodkrams):
        """Test exception"""

        # Define the replacement for the patched method:
        mock_response = MockResponse(notfound=True)
        methodkrams.return_value = mock_response

        # Call method and check result:
        with self.assertRaises(HandleNotFoundException):
            self.inst.is_URL_contained_in_10320loc('who/cares', url='http://bla')
        with self.assertRaises(HandleNotFoundException):
            self.inst.is_URL_contained_in_10320loc('who/cares', url=['http://bla','http://foo.foo'])


class MockRequest(object):
    def __init__(self, url=None):
        if url is not None:
            self.url = url
        else:
            self.url = 'http://foo.foo'
    
class MockResponse(object):
    def __init__(self, status_code=None, content=None, request=None, success=False, notfound=False, empty=False):

        self.content = None
        self.status_code = None
        self.request = None

        # Some predefined cases:
        if success:
            self.status_code = 200
            self.content = '{"responseCode":1}'
        elif notfound:
            self.status_code = 404
            self.content = '{"responseCode":100}'
        elif empty:
            self.status_code = 200
            self.content = '{"responseCode":200}'
        # User-defined overwrites predefined cases:
        if content is not None:
            self.content = content
        if status_code is not None:
            self.status_code = status_code
        if request is not None:
            self.request = request
        # Defaults (do not override):
        if self.content is None:    
            self.content = '{"responseCode":1}'
        if self.status_code is None:
            self.status_code = 200
        if self.request is None:
            self.request = MockRequest()

