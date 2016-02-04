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

    def get_payload_from_mockresponse(self, putpatch):
        # For help, please see: http://www.voidspace.org.uk/python/mock/examples.html#checking-multiple-calls-with-mock
        kwargs_passed_to_put = putpatch.call_args_list[len(putpatch.call_args_list)-1][1]
        passed_payload = None
        try:
            passed_payload = json.loads(kwargs_passed_to_put['data'])
            replace_timestamps(passed_payload)
        except KeyError:
            pass
        return passed_payload

    def get_kw_attribute_from_mockresponse(self, attrname, methodpatch):
        # For help, please see: http://www.voidspace.org.uk/python/mock/examples.html#checking-multiple-calls-with-mock
        kwargs_passed_to_patch = methodpatch.call_args_list[len(methodpatch.call_args_list)-1][1]
        passed_attr = kwargs_passed_to_patch[attrname]
        return passed_attr

    def get_pos_attribute_from_mockresponse(self, pos, methodpatch):
        posargs_passed_to_patch = methodpatch.call_args_list[len(methodpatch.call_args_list)-1][0]
        passed_attr = posargs_passed_to_patch[pos]
        return passed_attr

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

        # Define the replacement for the patched PUT method:
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
        passed_payload = self.get_payload_from_mockresponse(putpatch)

        # Compare with expected payload:
        expected_payload = {"values": list_of_entries}
        self.assertEqual(passed_payload, expected_payload,
            failure_message(expected=expected_payload, passed=passed_payload, methodname='put_request'))

    @patch('requests.Session.delete')
    def test_delete_request_via_cert(self, deletepatch):

        # Define the replacement for the patched DELETE method:
        mock_response_del = MockResponse(success=True)
        deletepatch.return_value = mock_response_del

        # Test variables
        handle = '123/456'

        # Run code to be tested
        self.inst.send_handle_delete_request(handle)

        # Check if the DELETE request was sent exactly once:
        self.assertEqual(deletepatch.call_count, 1,
            'The method "requests.delete" was not called once, but '+str(deletepatch.call_count)+' times.')

        # Get the payload+headers passed to "requests.delete"
        headers = self.get_kw_attribute_from_mockresponse('headers',deletepatch)

        # Compare with expected payload:
        self.assertEquals(headers['Authorization'], 'Handle clientCert="true"',
            'Authorization header not sent correctly: '+headers['Authorization'])

    @patch('requests.Session.delete')
    def test_delete_request_via_cert(self, deletepatch):

        # Define the replacement for the patched DELETE method:
        mock_response_del = MockResponse(success=True)
        deletepatch.return_value = mock_response_del

        # Test variables
        handle = '123/456'
        indices = [1,4,5]

        # Run code to be tested
        self.inst.send_handle_delete_request(handle, indices)

        # Check if the DELETE request was sent exactly once:
        self.assertEqual(deletepatch.call_count, 1,
            'The method "requests.delete" was not called once, but '+str(deletepatch.call_count)+' times.')

        # Get the url passed to "requests.delete"
        url = self.get_pos_attribute_from_mockresponse(0,deletepatch)

        # Compare with expected payload:
        self.assertIn('index=1', url, 'Index 1 missing')
        self.assertIn('index=4', url, 'Index 4 missing')
        self.assertIn('index=5', url, 'Index 5 missing')

    @patch('b2handle.handlesystemconnector.HandleSystemConnector.check_if_username_exists')
    @patch('requests.Session.delete')
    def test_delete_request_via_basic_auth(self, deletepatch, username_check_patch):

        # Make a new test instance with different authorization:
        inst = connector.HandleSystemConnector(
            username='300:user/name',
            password='mypassword',
            handle_server_url='http://foo.com'
        )

        # Define the replacement for the patched DELETE method:
        mock_response_del = MockResponse(success=True)
        deletepatch.return_value = mock_response_del

        # Define replacement for the patched check for username existence:
        username_check_patch = mock.Mock()
        username_check_patch.response_value = True

        # Test variables
        handle = '123/456'

        # Run code to be tested
        inst.send_handle_delete_request(handle)

        # Check if the DELETE request was sent exactly once:
        self.assertEqual(deletepatch.call_count, 1,
            'The method "requests.delete" was not called once, but '+str(deletepatch.call_count)+' times.')

        # Get the payload+headers passed to "requests.delete"
        headers = self.get_kw_attribute_from_mockresponse('headers',deletepatch)

        # Compare with expected payload:
        self.assertIn('Basic ', headers['Authorization'],
            'Authorization header not sent correctly: '+headers['Authorization'])

