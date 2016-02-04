"""Testing methods that need no server access."""

import sys
if sys.version_info < (2, 7):
    import unittest2 as unittest
else:
    import unittest
import json
import mock
from mock import patch
sys.path.append("../..")
import b2handle.handlesystemconnector as connector
from b2handle.handleexceptions import HandleSyntaxError
from b2handle.handleexceptions import CredentialsFormatError
from b2handle.util import check_handle_syntax, check_handle_syntax_with_index, remove_index_from_handle
from mockresponses import MockResponse, MockSearchResponse
from utilities import replace_timestamps, failure_message


class EUDATHandleConnectorWriteaccessPatchedTestCase(unittest.TestCase):

    def setUp(self):

        self.inst = connector.HandleSystemConnector(
            certificate_and_key='./testcredentials/fake_certi_and_bothkeys.pem',
            handle_server_url='http://foo.com'
        )

    def get_payload_headers_from_mockresponse(self, putpatch):
        # For help, please see: http://www.voidspace.org.uk/python/mock/examples.html#checking-multiple-calls-with-mock
        kwargs_passed_to_put = putpatch.call_args_list[len(putpatch.call_args_list)-1][1]
        passed_payload = json.loads(kwargs_passed_to_put['data'])
        replace_timestamps(passed_payload)
        passed_headers = kwargs_passed_to_put['headers']
        return passed_payload, passed_headers

    @patch('requests.Session.get')
    def test_get_request(self, getpatch):

        # Define the replacement for the patched GET method:
        mock_response_get = MockResponse()
        getpatch.return_value = mock_response_get

        # Test variables
        handle = '123/456'

        # Run code to be tested
        self.inst.send_handle_get_request(handle)

        # Check if the GET request was sent exactly once:
        self.assertEqual(getpatch.call_count, 1,
            'The method "requests.get" was not called once, but '+str(getpatch.call_count)+' times.')

    @patch('requests.Session.put')
    def test_put_request(self, putpatch):

        # Define the replacement for the patched GET method:
        mock_response_put = MockResponse(wascreated=True)
        putpatch.return_value = mock_response_put

        # Test variables
        handle = '123/456'
        list_of_entries = [{"index":2, "type":"xyz", "data":"xyz"}]

        # Run code to be tested
        self.inst.send_handle_put_request(handle, list_of_entries)

        # Check if the PUT request was sent exactly once:
        self.assertEqual(putpatch.call_count, 1,
            'The method "requests.put" was not called once, but '+str(putpatch.call_count)+' times.')

        # Get the payload+headers passed to "requests.put"
        passed_payload, _ = self.get_payload_headers_from_mockresponse(putpatch)

        # Compare with expected payload:
        expected_payload = {"values": list_of_entries}
        self.assertEqual(passed_payload, expected_payload,
            failure_message(expected=expected_payload, passed=passed_payload, methodname='put_request'))