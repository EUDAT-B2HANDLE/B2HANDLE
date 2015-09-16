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

        # Call method and check result:
        json_record = self.inst.retrieve_handle_record_json('test/handle')
        expected = json.loads(handlerecord)
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

