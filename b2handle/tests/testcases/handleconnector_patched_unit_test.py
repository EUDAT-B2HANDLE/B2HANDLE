"""Testing methods that need no server access."""

import sys
if sys.version_info < (2, 7):
    import unittest2 as unittest
else:
    import unittest

import json
import mock
import b2handle
import b2handle.handlesystemconnector as connector
from b2handle.handleexceptions import HandleSyntaxError, CredentialsFormatError, GenericHandleError, HandleNotFoundException
from b2handle.utilhandle import check_handle_syntax, check_handle_syntax_with_index, remove_index_from_handle
from b2handle.tests.mockresponses import MockResponse, MockSearchResponse
from b2handle.tests.utilities import replace_timestamps, failure_message

# Load some data that is needed for testing
PATH_CRED = b2handle.util.get_neighbour_directory(__file__, 'testcredentials')
CRED_FILE = PATH_CRED+'/fake_certs_and_keys/fake_certi_and_bothkeys.pem'
PATH_RES = b2handle.util.get_neighbour_directory(__file__, 'resources')
RECORD = open(PATH_RES+'/handlerecord_for_reading_PUBLIC.json').read()

class EUDATHandleConnectorAccessPatchedTestCase(unittest.TestCase):

    def setUp(self):

        self.inst = connector.HandleSystemConnector(
            certificate_and_key=CRED_FILE,
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

    @mock.patch('requests.Session.get')
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

    @mock.patch('requests.Session.put')
    def test_put_request(self, putpatch):

        # Define the replacement for the patched PUT method:
        mock_response_put = MockResponse(wascreated=True)
        putpatch.return_value = mock_response_put

        # Test variables
        handle = '123/456'
        list_of_entries = [{"index":2, "type":"XYZ", "data":"xyz"}]

        # Run code to be tested
        self.inst.send_handle_put_request(handle=handle, list_of_entries=list_of_entries)

        # Check if the PUT request was sent exactly once:
        self.assertEqual(putpatch.call_count, 1,
            'The method "requests.put" was not called once, but '+str(putpatch.call_count)+' times.')

        # Get the payload+headers passed to "requests.put"
        passed_payload = self.get_payload_from_mockresponse(putpatch)

        # Compare with expected payload:
        expected_payload = {"values": list_of_entries}
        self.assertEqual(passed_payload, expected_payload,
            failure_message(expected=expected_payload, passed=passed_payload, methodname='put_request'))

    @mock.patch('requests.Session.delete')
    def test_delete_request_via_cert(self, deletepatch):

        # Define the replacement for the patched DELETE method:
        mock_response_del = MockResponse(success=True)
        deletepatch.return_value = mock_response_del

        # Test variables
        handle = '123/456'

        # Run code to be tested
        self.inst.send_handle_delete_request(handle=handle)

        # Check if the DELETE request was sent exactly once:
        self.assertEqual(deletepatch.call_count, 1,
            'The method "requests.delete" was not called once, but '+str(deletepatch.call_count)+' times.')

        # Get the payload+headers passed to "requests.delete"
        headers = self.get_kw_attribute_from_mockresponse('headers',deletepatch)

        # Compare with expected payload:
        self.assertEquals(headers['Authorization'], 'Handle clientCert="true"',
            'Authorization header not sent correctly: '+headers['Authorization'])

    @mock.patch('requests.Session.delete')
    def test_delete_request_via_cert(self, deletepatch):

        # Define the replacement for the patched DELETE method:
        mock_response_del = MockResponse(success=True)
        deletepatch.return_value = mock_response_del

        # Test variables
        handle = '123/456'
        indices = [1,4,5]

        # Run code to be tested
        self.inst.send_handle_delete_request(handle=handle, indices=indices)

        # Check if the DELETE request was sent exactly once:
        self.assertEqual(deletepatch.call_count, 1,
            'The method "requests.delete" was not called once, but '+str(deletepatch.call_count)+' times.')

        # Get the url passed to "requests.delete"
        url = self.get_pos_attribute_from_mockresponse(0,deletepatch)

        # Compare with expected payload:
        self.assertIn('index=1', url, 'Index 1 missing')
        self.assertIn('index=4', url, 'Index 4 missing')
        self.assertIn('index=5', url, 'Index 5 missing')

    @mock.patch('b2handle.handlesystemconnector.HandleSystemConnector.check_if_username_exists')
    @mock.patch('requests.Session.delete')
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
        inst.send_handle_delete_request(handle=handle)

        # Check if the DELETE request was sent exactly once:
        self.assertEqual(deletepatch.call_count, 1,
            'The method "requests.delete" was not called once, but '+str(deletepatch.call_count)+' times.')

        # Get the payload+headers passed to "requests.delete"
        headers = self.get_kw_attribute_from_mockresponse('headers',deletepatch)

        # Compare with expected payload:
        self.assertIn('Basic ', headers['Authorization'],
            'Authorization header not sent correctly: '+headers['Authorization'])

    # check if username exists

    @mock.patch('requests.Session.get')
    def test_check_if_username_exists_normal(self, getpatch):
        """Test whether username exists."""

        # Test variables
        handlerecord_string = RECORD
        handlerecord_json = json.loads(handlerecord_string)
        testhandle = '100:'+handlerecord_json['handle']

        # Define the replacement for the patched method:
        mock_response = MockResponse(success=True, content=handlerecord_string)
        getpatch.return_value = mock_response

        # Call method and check result:
        res = self.inst.check_if_username_exists(testhandle)
        self.assertTrue(res,
            'The handle exists, so "check_if_username_exists" should return true!')

    @mock.patch('requests.Session.get')
    def test_check_if_username_exists_inconsistent_info(self, getpatch):
        """Test exception when contradictory inputs are given."""
    
        # Test variables
        handlerecord_string = RECORD
        testhandle = 'who/cares'

        # Define the replacement for the patched method:
        mock_response = MockResponse(success=True, content=handlerecord_string)
        getpatch.return_value = mock_response

        # Call method and check result:
        with self.assertRaises(GenericHandleError):
            self.inst.check_if_username_exists(testhandle)

    @mock.patch('requests.Session.get')
    def test_check_if_username_exists_it_doesnot(self, getpatch):
        """Test exception"""

        # Test variables
        testhandle = 'who/cares'
        
        # Define the replacement for the patched method:
        mock_response = MockResponse(notfound=True)
        getpatch.return_value = mock_response

        # Call method and check result:
        with self.assertRaises(HandleNotFoundException):
            self.inst.check_if_username_exists(testhandle)
