"""Testing methods that normally need Handle server read access,
by patching the get request to replace read access."""

import unittest
import json
import sys
import mock
from mock import patch
sys.path.append("../..")
from b2handle.handleclient import EUDATHandleClient
from b2handle.handleexceptions import HandleAlreadyExistsException
from b2handle.handleexceptions import HandleAuthenticationError
from b2handle.handleexceptions import HandleNotFoundException
from b2handle.handleexceptions import BrokenHandleRecordException
from b2handle.handleexceptions import IllegalOperationException
from b2handle.handleexceptions import ReverseLookupException
from b2handle.handleexceptions import GenericHandleError
from mockresponses import MockResponse, MockSearchResponse
from utilities import failure_message, replace_timestamps, sort_lists

class EUDATHandleClientWriteaccessPatchedTestCase(unittest.TestCase):
    '''Testing methods with write access (patched server access).

    The tests work by intercepting all HTTP put requests and comparing their payload to
    the payload of successful real put requests from previous integration tests.

    The payloads from previous tests were collected by a logger in the integration
    tests (look for REQUESTLOGGER in the write-integration test code). Of course,
    the names of the handles have to be adapted in there.

    Comparison it done by python dictionary comparison, which ignores
    the order of the record entries, whitespace, string separators and
    whether keys are unicode strings or normal strings.

    The timestamps should not be compared, so they should be removed. For this,
    there is a method "replace_timestamps".
    '''

    @patch('b2handle.handleclient.EUDATHandleClient.check_if_username_exists')
    def setUp(self, username_check_patch):

        # Define replacement for the patched check for username existence:
        username_check_patch = mock.Mock()
        username_check_patch.response_value = True

        # Create a client instance for write access:
        self.inst = EUDATHandleClient.instantiate_with_username_and_password('http://handle.server', '999:user/name', 'apassword')

    def tearDown(self):
        pass
        pass

    def get_payload_headers_from_mockresponse(self, putpatch):
        # For help, please see: http://www.voidspace.org.uk/python/mock/examples.html#checking-multiple-calls-with-mock
        kwargs_passed_to_put = putpatch.call_args_list[len(putpatch.call_args_list)-1][1]
        passed_payload = json.loads(kwargs_passed_to_put['data'])
        replace_timestamps(passed_payload)
        passed_headers = kwargs_passed_to_put['headers']
        return passed_payload, passed_headers

    # register_handle

    @patch('b2handle.handleclient.requests.put')
    @patch('b2handle.handleclient.requests.get')
    def test_register_handle(self, getpatch, putpatch):
        """Test registering a new handle with various types of values."""

        # Define the replacement for the patched GET method:
        # The handle does not exist yet, so a response with 404
        mock_response_get = MockResponse(notfound=True)
        getpatch.return_value = mock_response_get

        # Define the replacement for the patched requests.put method:
        mock_response_put = MockResponse(wascreated=True)
        putpatch.return_value = mock_response_put

        # Run the code to be tested:
        testhandle = 'my/testhandle'
        testlocation = 'http://foo.bar'
        testchecksum = '123456'
        additional_URLs = ['http://bar.bar', 'http://foo.foo']
        handle_returned = self.inst.register_handle(testhandle,
                                                    location=testlocation,
                                                    checksum=testchecksum,
                                                    additional_URLs=additional_URLs,
                                                    foo='foo',
                                                    bar='bar')


        # Check if the PUT request was sent exactly once:
        self.assertEqual(putpatch.call_count, 1,
            'The method "requests.put" was not called once, but '+str(putpatch.call_count)+' times.')

        # Get the payload+headers passed to "requests.put"
        passed_payload, _ = self.get_payload_headers_from_mockresponse(putpatch)

        # Compare with expected payload:
        expected_payload = {"values": [{"index": 100, "type": "HS_ADMIN", "data": {"value": {"index": "999", "handle": "user/name", "permissions": "011111110011"}, "format": "admin"}}, {"index": 1, "type": "URL", "data": "http://foo.bar"}, {"index": 2, "type": "CHECKSUM", "data": "123456"}, {"index": 3, "type": "foo", "data": "foo"}, {"index": 4, "type": "bar", "data": "bar"}, {"index": 5, "type": "10320/LOC", "data": "<locations><location href=\"http://bar.bar\" id=\"0\" /><location href=\"http://foo.foo\" id=\"1\" /></locations>"}]}
        replace_timestamps(expected_payload)
        self.assertEqual(passed_payload, expected_payload,
            failure_message(expected=expected_payload, passed=passed_payload, methodname='register_handle'))

    @patch('b2handle.handleclient.requests.put')
    @patch('b2handle.handleclient.requests.get')
    def test_register_handle_already_exists(self, getpatch, putpatch):
        """Test if overwrite=False prevents handle overwriting."""

        # Define the replacement for the patched GET method:
        mock_response_get = MockResponse(success=True)
        getpatch.return_value = mock_response_get

        # Run code to be tested + check exception:
        with self.assertRaises(HandleAlreadyExistsException):
            self.inst.register_handle('my/testhandle',
                                      'http://foo.foo',
                                      test1='I am just an illusion.',
                                      overwrite=False)

        # Check if nothing was changed (PUT should not have been called):
        self.assertEqual(putpatch.call_count, 0,
            'The method "requests.put" was called! ('+str(putpatch.call_count)+' times). It should NOT have been called.')

    @patch('b2handle.handleclient.requests.put')
    @patch('b2handle.handleclient.requests.get')
    def test_register_handle_already_exists_overwrite(self, getpatch, putpatch):
        """Test registering an existing handle with various types of values, with overwrite=True."""

        # Define the replacement for the patched GET method:
        mock_response_get = MockResponse(success=True)
        getpatch.return_value = mock_response_get

        # Define the replacement for the patched requests.put method:
        mock_response_put = MockResponse(wascreated=True)
        putpatch.return_value = mock_response_put

        # Run the method to be tested:
        testhandle = 'my/testhandle'
        testlocation = 'http://foo.bar'
        testchecksum = '123456'
        overwrite = True
        additional_URLs = ['http://bar.bar', 'http://foo.foo']
        handle_returned = self.inst.register_handle(testhandle,
                                                    location=testlocation,
                                                    checksum=testchecksum,
                                                    additional_URLs=additional_URLs,
                                                    overwrite=overwrite,
                                                    foo='foo',
                                                    bar='bar')

        # Check if the PUT request was sent exactly once:
        self.assertEqual(putpatch.call_count, 1,
            'The method "requests.put" was not called once, but '+str(putpatch.call_count)+' times.')

        # Get the payload+headers passed to "requests.put"
        passed_payload, passed_headers = self.get_payload_headers_from_mockresponse(putpatch)

        # Compare with expected payload:
        expected_payload = {"values": [{"index": 100, "type": "HS_ADMIN", "data": {"value": {"index": "999", "handle": "user/name", "permissions": "011111110011"}, "format": "admin"}}, {"index": 1, "type": "URL", "data": "http://foo.bar"}, {"index": 2, "type": "CHECKSUM", "data": "123456"}, {"index": 3, "type": "foo", "data": "foo"}, {"index": 4, "type": "bar", "data": "bar"}, {"index": 5, "type": "10320/LOC", "data": "<locations><location href=\"http://bar.bar\" id=\"0\" /><location href=\"http://foo.foo\" id=\"1\" /></locations>"}]}
        replace_timestamps(expected_payload)
        self.assertEqual(passed_payload, expected_payload,
            failure_message(expected=expected_payload, passed=passed_payload, methodname='register_handle'))

        # Check if requests.put received an authorization header:
        self.assertIn('Authorization', passed_headers,
            'Authorization header not passed: '+str(passed_headers))

    # generate_and_register_handle

    @patch('b2handle.handleclient.requests.put')
    @patch('b2handle.handleclient.requests.get')
    def test_generate_and_register_handle(self, getpatch, putpatch):
        """Test generating and registering a new handle."""

        # Define the replacement for the patched GET method:
        mock_response_get = MockResponse(notfound=True)
        getpatch.return_value = mock_response_get
        # Define the replacement for the patched requests.put method:
        mock_response_put = MockResponse(wascreated=True)
        putpatch.return_value = mock_response_put

        # Run the method to be tested:
        testlocation = 'http://foo.bar'
        testchecksum = '123456'
        handle_returned = self.inst.generate_and_register_handle(
            prefix='my',
            location=testlocation,
            checksum=testchecksum)

        # Check if the PUT request was sent exactly once:
        self.assertEqual(putpatch.call_count, 1,
            'The method "requests.put" was not called once, but '+str(putpatch.call_count)+' times.')

        # Get the payload+headers passed to "requests.put"
        passed_payload, _ = self.get_payload_headers_from_mockresponse(putpatch)

        # Compare with expected payload:
        expected_payload = {"values": [{"index": 100, "type": "HS_ADMIN", "data": {"value": {"index": "999", "handle": "user/name", "permissions": "011111110011"}, "format": "admin"}}, {"index": 1, "type": "URL", "data": "http://foo.bar"}, {"index": 2, "type": "CHECKSUM", "data": "123456"}]}
        replace_timestamps(expected_payload)
        self.assertEqual(passed_payload, expected_payload,
            failure_message(expected=expected_payload, passed=passed_payload, methodname='generate_and_register_handle'))

    # modify_handle_value

    @patch('b2handle.handleclient.requests.put')
    @patch('b2handle.handleclient.requests.get')
    def test_modify_handle_value_one(self, getpatch, putpatch):
        """Test modifying one existing handle value."""

        # Define the replacement for the patched GET method:
        cont = {"responseCode":1,"handle":"my/testhandle","values":[{"index":111,"type":"test1","data":{"format":"string","value":"val1"},"ttl":86400,"timestamp":"2015-09-29T15:51:08Z"},{"index":2222,"type":"test2","data":{"format":"string","value":"val2"},"ttl":86400,"timestamp":"2015-09-29T15:51:08Z"},{"index":333,"type":"test3","data":{"format":"string","value":"val3"},"ttl":86400,"timestamp":"2015-09-29T15:51:08Z"},{"index":4,"type":"test4","data":{"format":"string","value":"val4"},"ttl":86400,"timestamp":"2015-09-29T15:51:08Z"}]}
        mock_response_get = MockResponse(status_code=200, content=json.dumps(cont))
        getpatch.return_value = mock_response_get

        # Define the replacement for the patched requests.put method:
        cont = {"responseCode":1,"handle":"my/testhandle"}
        mock_response_put = MockResponse(status_code=200, content=json.dumps(cont))
        putpatch.return_value = mock_response_put

        # Run the method to be tested:
        testhandle = 'my/testhandle'
        self.inst.modify_handle_value(testhandle, test4='newvalue')

        # Check if the PUT request was sent exactly once:
        self.assertEqual(putpatch.call_count, 1,
            'The method "requests.put" was not called once, but '+str(putpatch.call_count)+' times.')

        # Get the payload passed to "requests.put"
        passed_payload, _ = self.get_payload_headers_from_mockresponse(putpatch)

        # Compare with expected payload:
        expected_payload = {"values": [{"index": 4, "ttl": 86400, "type": "test4", "data": "newvalue"}, {"index": 111, "ttl": 86400, "type": "test1", "timestamp": "2015-09-30T13:57:03Z", "data": {"value": "val1", "format": "string"}}, {"index": 2222, "ttl": 86400, "type": "test2", "timestamp": "2015-09-30T13:57:03Z", "data": {"value": "val2", "format": "string"}}, {"index": 333, "ttl": 86400, "type": "test3", "timestamp": "2015-09-30T13:57:03Z", "data": {"value": "val3", "format": "string"}}]}
        replace_timestamps(expected_payload)
        self.assertEqual(passed_payload, expected_payload,
            failure_message(expected=expected_payload,
                                 passed=passed_payload,
                                 methodname='modify_handle_value'))

    @patch('b2handle.handleclient.requests.put')
    @patch('b2handle.handleclient.requests.get')
    def test_modify_handle_value_several(self, getpatch, putpatch):
        """Test modifying several existing handle values."""

        # Define the replacement for the patched GET method:
        cont = {
            "responseCode":1,
            "handle":"my/testhandle",
            "values":[
            {
                "index":111,
                "type":"test1",
                "data":{
                    "format":"string",
                    "value":"val1"
                },
                "ttl":86400,
                "timestamp":"2015-09-29T15:51:08Z"
            },{
                "index":2222,
                "type":"test2",
                "data":{
                    "format":"string",
                    "value":"val2"
                },
                "ttl":86400,
                "timestamp":"2015-09-29T15:51:08Z"
            },{
                "index":333,
                "type":"test3",
                "data":{
                    "format":"string",
                    "value":"val3"
                },
                "ttl":86400,
                "timestamp":"2015-09-29T15:51:08Z"
            },{
                "index":4,
                "type":"test4",
                "data":{
                    "format":"string",
                    "value":"val4"
                },
                "ttl":86400,
                "timestamp":"2015-09-29T15:51:08Z"
            }]
        }
        mock_response_get = MockResponse(status_code=200, content=json.dumps(cont))
        getpatch.return_value = mock_response_get

        # Define the replacement for the patched requests.delete method:
        mock_response_put = MockResponse()
        putpatch.return_value = mock_response_put

        # Test variables
        testhandle = 'my/testhandle'

        # Run the method to be tested:
        self.inst.modify_handle_value(testhandle,
                                          test4='new4',
                                          test2='new2',
                                          test3='new3')

        # Check if the PUT request was sent exactly once:
        self.assertEqual(putpatch.call_count, 1,
            'The method "requests.put" was not called once, but '+str(putpatch.call_count)+' times.')

        # Get the payload passed to "requests.put"
        passed_payload, _ = self.get_payload_headers_from_mockresponse(putpatch)
        sort_lists(passed_payload)

        # Compare with expected payload:
        expected_payload = {
        "values":[
            {
                "index":111,
                "type":"test1",
                "data":{
                    "format":"string",
                    "value":"val1"
                },
                "ttl":86400,
                "timestamp":"2015-09-29T15:51:08Z"
            },{
                "index":2222,
                "type":"test2",
                "data":"new2",
                "ttl":86400,
            },{
                "index":333,
                "type":"test3",
                "data":"new3",
                "ttl":86400,
            },{
                "index":4,
                "type":"test4",
                "data":"new4",
                "ttl":86400,
            }]
        }
        replace_timestamps(expected_payload)
        sort_lists(expected_payload)
        self.assertEqual(passed_payload, expected_payload,
            failure_message(expected=expected_payload,
                                 passed=passed_payload,
                                 methodname='modify_handle_value'))

    @patch('b2handle.handleclient.requests.put')
    @patch('b2handle.handleclient.requests.get')
    def test_modify_handle_value_corrupted(self, getpatch, putpatch):
        """Test exception when trying to modify corrupted handle record."""

        # Define the replacement for the patched GET method (getting a corrupted record):
        cont = {"responseCode":1,"handle":"my/testhandle","values":[{"index":111,"type":"test1","data":{"format":"string","value":"val1"},"ttl":86400,"timestamp":"2015-09-30T15:08:49Z"},{"index":2222,"type":"test2","data":{"format":"string","value":"val2"},"ttl":86400,"timestamp":"2015-09-30T15:08:49Z"},{"index":333,"type":"test2","data":{"format":"string","value":"val3"},"ttl":86400,"timestamp":"2015-09-30T15:08:49Z"},{"index":4,"type":"test4","data":{"format":"string","value":"val4"},"ttl":86400,"timestamp":"2015-09-30T15:08:49Z"}]}
        mock_response_get = MockResponse(status_code=200, content=json.dumps(cont))
        getpatch.return_value = mock_response_get

        # Define the replacement for the patched requests.put method:
        cont = {"responseCode":1,"handle":"my/testhandle"}
        mock_response_put = MockResponse(status_code=200, content=json.dumps(cont))
        putpatch.return_value = mock_response_put

        # Call the method to be tested: Modifying corrupted raises exception:
        with self.assertRaises(BrokenHandleRecordException):
            self.inst.modify_handle_value('my/testhandle',
                                          test4='new4',
                                          test2='new2',
                                          test3='new3')

        # Check if PUT was called (PUT should not have been called):
        self.assertEqual(putpatch.call_count, 0,
            'The method "requests.put" was called! ('+str(putpatch.call_count)+' times). It should NOT have been called.')

    @patch('b2handle.handleclient.requests.delete')
    @patch('b2handle.handleclient.requests.get')
    def test_modify_handle_value_without_authentication(self, getpatch, putpatch):
        """Test if exception when not authenticated."""

        # Define the replacement for the patched GET method:
        cont = {"responseCode":1,"handle":"my/testhandle","values":[{"index":111,"type":"test1","data":{"format":"string","value":"val1"},"ttl":86400,"timestamp":"2015-09-29T15:51:08Z"},{"index":2222,"type":"test2","data":{"format":"string","value":"val2"},"ttl":86400,"timestamp":"2015-09-29T15:51:08Z"},{"index":333,"type":"test3","data":{"format":"string","value":"val3"},"ttl":86400,"timestamp":"2015-09-29T15:51:08Z"},{"index":4,"type":"test4","data":{"format":"string","value":"val4"},"ttl":86400,"timestamp":"2015-09-29T15:51:08Z"}]}
        mock_response_get = MockResponse(status_code=200, content=json.dumps(cont))
        getpatch.return_value = mock_response_get

        # Define the replacement for the patched requests.delete method:
        mock_response_put = MockResponse()
        putpatch.return_value = mock_response_put

        # Test variables
        inst_readonly = EUDATHandleClient('http://foo.com', HTTP_verify=True)
        testhandle = 'my/testhandle'

        # Run code to be tested and check exception:
        with self.assertRaises(HandleAuthenticationError):
            inst_readonly.modify_handle_value(testhandle, foo='bar')

    @patch('b2handle.handleclient.requests.put')
    @patch('b2handle.handleclient.requests.get')
    def test_modify_handle_value_several_inexistent(self, getpatch, putpatch):
        """Test modifying several existing handle values, one of them inexistent."""

        # Define the replacement for the patched GET method:
        cont = {"responseCode":1,"handle":"my/testhandle","values":[{"index":111,"type":"test1","data":{"format":"string","value":"val1"},"ttl":86400,"timestamp":"2015-09-29T15:51:08Z"},{"index":2222,"type":"test2","data":{"format":"string","value":"val2"},"ttl":86400,"timestamp":"2015-09-29T15:51:08Z"},{"index":333,"type":"test3","data":{"format":"string","value":"val3"},"ttl":86400,"timestamp":"2015-09-29T15:51:08Z"},{"index":4,"type":"test4","data":{"format":"string","value":"val4"},"ttl":86400,"timestamp":"2015-09-29T15:51:08Z"}]}
        mock_response_get = MockResponse(status_code=200, content=json.dumps(cont))
        getpatch.return_value = mock_response_get

        # Define the replacement for the patched requests.delete method:
        mock_response_put = MockResponse()
        putpatch.return_value = mock_response_put

        # Test variables
        testhandle = 'my/testhandle'

        # Run the method to be tested:
        self.inst.modify_handle_value(testhandle,
                                          test4='new4',
                                          test2='new2',
                                          test100='new100')

        # Check if the PUT request was sent exactly once:
        self.assertEqual(putpatch.call_count, 1,
            'The method "requests.put" was not called once, but '+str(putpatch.call_count)+' times.')

        # Get the payload passed to "requests.put"
        passed_payload, _ = self.get_payload_headers_from_mockresponse(putpatch)

        # Compare with expected payload:
        expected_payload = {"values": [{"index": 2, "type": "test100", "data": "new100"}, {"index": 2222, "ttl": 86400, "type": "test2", "data": "new2"}, {"index": 4, "ttl": 86400, "type": "test4", "data": "new4"}, {"index": 111, "ttl": 86400, "type": "test1", "timestamp": "2015-09-30T20:38:59Z", "data": {"value": "val1", "format": "string"}}, {"index": 333, "ttl": 86400, "type": "test3", "timestamp": "2015-09-30T20:38:59Z", "data": {"value": "val3", "format": "string"}}]}
        replace_timestamps(expected_payload)
        self.assertEqual(passed_payload, expected_payload,
            failure_message(expected=expected_payload,
                                 passed=passed_payload,
                                 methodname='modify_handle_value'))

    @patch('b2handle.handleclient.requests.put')
    @patch('b2handle.handleclient.requests.get')
    def test_modify_handle_value_HS_ADMIN(self, getpatch, putpatch):
        """Test exception when trying to modify HS_ADMIN."""

        # Define the replacement for the patched GET method:
        cont = {"responseCode":1,"handle":"my/testhandle","values":[{"index":111,"type":"test1","data":{"format":"string","value":"val1"},"ttl":86400,"timestamp":"2015-09-29T15:51:08Z"},{"index":2222,"type":"test2","data":{"format":"string","value":"val2"},"ttl":86400,"timestamp":"2015-09-29T15:51:08Z"},{"index":333,"type":"test3","data":{"format":"string","value":"val3"},"ttl":86400,"timestamp":"2015-09-29T15:51:08Z"},{"index":4,"type":"test4","data":{"format":"string","value":"val4"},"ttl":86400,"timestamp":"2015-09-29T15:51:08Z"}]}
        mock_response_get = MockResponse(status_code=200, content=json.dumps(cont))
        getpatch.return_value = mock_response_get

        # Define the replacement for the patched requests.delete method:
        mock_response_put = MockResponse()
        putpatch.return_value = mock_response_put

        # Test variables
        testhandle = 'my/testhandle'

        # Run the method to be tested and check exception:
        with self.assertRaises(IllegalOperationException):
                self.inst.modify_handle_value(testhandle, HS_ADMIN='please let me in!')


    # delete_handle_value:

    @patch('b2handle.handleclient.requests.delete')
    @patch('b2handle.handleclient.requests.get')
    def test_delete_handle_value_one_entry(self, getpatch, deletepatch):
        """Test deleting one entry from a record."""

        # Define the replacement for the patched GET method:
        cont = {"responseCode":1,"handle":"my/testhandle","values":[{"index":111,"type":"test1","data":{"format":"string","value":"val1"},"ttl":86400,"timestamp":"2015-09-30T15:08:49Z"},{"index":2222,"type":"test2","data":{"format":"string","value":"val2"},"ttl":86400,"timestamp":"2015-09-30T15:08:49Z"},{"index":333,"type":"test2","data":{"format":"string","value":"val3"},"ttl":86400,"timestamp":"2015-09-30T15:08:49Z"},{"index":4,"type":"test4","data":{"format":"string","value":"val4"},"ttl":86400,"timestamp":"2015-09-30T15:08:49Z"}]}
        mock_response_get = MockResponse(status_code=200, content=json.dumps(cont))
        getpatch.return_value = mock_response_get

        # Define the replacement for the patched requests.delete method:
        mock_response_del = MockResponse()
        deletepatch.return_value = mock_response_del

        # Call the method to be tested:
        self.inst.delete_handle_value('my/testhandle', 'test1')

        # Get the args passed to "requests.delete"
        # For help, please see: http://www.voidspace.org.uk/python/mock/examples.html#checking-multiple-calls-with-mock
        positional_args_passed_to_delete = deletepatch.call_args_list[len(deletepatch.call_args_list)-1][0]
        passed_url = positional_args_passed_to_delete[0]

        # Compare with expected URL:
        self.assertIn('?index=111',passed_url,
            'The index 111 is not specified in the URL '+passed_url+'. This is serious!')

    @patch('b2handle.handleclient.requests.delete')
    @patch('b2handle.handleclient.requests.get')
    def test_delete_handle_value_several_entries(self, getpatch, deletepatch):
        """Test deleting several entries from a record."""

        # Test variables
        testhandle = 'my/testhandle'

        # Define the replacement for the patched GET method:
        cont = {"responseCode":1,"handle":testhandle,"values":[{"index":111,"type":"test1","data":{"format":"string","value":"val1"},"ttl":86400,"timestamp":"2015-09-30T15:08:49Z"},{"index":2222,"type":"test2","data":{"format":"string","value":"val2"},"ttl":86400,"timestamp":"2015-09-30T15:08:49Z"},{"index":333,"type":"test2","data":{"format":"string","value":"val3"},"ttl":86400,"timestamp":"2015-09-30T15:08:49Z"},{"index":4,"type":"test4","data":{"format":"string","value":"val4"},"ttl":86400,"timestamp":"2015-09-30T15:08:49Z"}]}
        mock_response_get = MockResponse(status_code=200, content=json.dumps(cont))
        getpatch.return_value = mock_response_get

        # Define the replacement for the patched requests.delete method:
        mock_response_del = MockResponse()
        deletepatch.return_value = mock_response_del

        # Call the method to be tested:
        self.inst.delete_handle_value(testhandle, ['test1', 'test2'])

        # Get the args passed to "requests.delete"
        # For help, please see: http://www.voidspace.org.uk/python/mock/examples.html#checking-multiple-calls-with-mock
        positional_args_passed_to_delete = deletepatch.call_args_list[len(deletepatch.call_args_list)-1][0]
        passed_url = positional_args_passed_to_delete[0]

        # Compare with expected URL:
        self.assertIn('index=111',passed_url,
            'The index 111 is not specified in the URL '+passed_url+'. This may be serious!')
        self.assertIn('index=222',passed_url,
            'The index 2222 is not specified in the URL '+passed_url+'. This may be serious!')

    @patch('b2handle.handleclient.requests.delete')
    @patch('b2handle.handleclient.requests.get')
    def test_delete_handle_value_inexistent_entry(self, getpatch, deletepatch):
        """Test deleting one inexistent entry from a record."""

        # Test variables
        testhandle = 'my/testhandle'

        # Define the replacement for the patched GET method:
        cont = {"responseCode":1,"handle":testhandle,"values":[{"index":111,"type":"test1","data":{"format":"string","value":"val1"},"ttl":86400,"timestamp":"2015-09-30T15:08:49Z"},{"index":2222,"type":"test2","data":{"format":"string","value":"val2"},"ttl":86400,"timestamp":"2015-09-30T15:08:49Z"},{"index":333,"type":"test2","data":{"format":"string","value":"val3"},"ttl":86400,"timestamp":"2015-09-30T15:08:49Z"},{"index":4,"type":"test4","data":{"format":"string","value":"val4"},"ttl":86400,"timestamp":"2015-09-30T15:08:49Z"}]}
        mock_response_get = MockResponse(status_code=200, content=json.dumps(cont))
        getpatch.return_value = mock_response_get

        # Define the replacement for the patched requests.delete method:
        mock_response_del = MockResponse()
        deletepatch.return_value = mock_response_del

        # Call the method to be tested:
        self.inst.delete_handle_value(testhandle, 'test100')

        # Check if PUT was called (PUT should not have been called):
        self.assertEqual(deletepatch.call_count, 0,
            'The method "requests.put" was called! ('+str(deletepatch.call_count)+' times). It should NOT have been called.')

    @patch('b2handle.handleclient.requests.delete')
    @patch('b2handle.handleclient.requests.get')
    def test_delete_handle_value_several_entries_one_nonexistent(self, getpatch, deletepatch):
        """Test deleting several entries from a record, one of them does not exist."""

        # Test variables
        testhandle = 'my/testhandle'

        # Define the replacement for the patched GET method:
        cont = {"responseCode":1,"handle":testhandle,"values":[{"index":111,"type":"test1","data":{"format":"string","value":"val1"},"ttl":86400,"timestamp":"2015-09-30T15:08:49Z"},{"index":2222,"type":"test2","data":{"format":"string","value":"val2"},"ttl":86400,"timestamp":"2015-09-30T15:08:49Z"},{"index":333,"type":"test2","data":{"format":"string","value":"val3"},"ttl":86400,"timestamp":"2015-09-30T15:08:49Z"},{"index":4,"type":"test4","data":{"format":"string","value":"val4"},"ttl":86400,"timestamp":"2015-09-30T15:08:49Z"}]}
        mock_response_get = MockResponse(status_code=200, content=json.dumps(cont))
        getpatch.return_value = mock_response_get

        # Define the replacement for the patched requests.delete method:
        mock_response_del = MockResponse()
        deletepatch.return_value = mock_response_del

        # Call the method to be tested:
        self.inst.delete_handle_value(testhandle, ['test1', 'test100'])

        # Get the args passed to "requests.delete"
        # For help, please see: http://www.voidspace.org.uk/python/mock/examples.html#checking-multiple-calls-with-mock
        positional_args_passed_to_delete = deletepatch.call_args_list[len(deletepatch.call_args_list)-1][0]
        passed_url = positional_args_passed_to_delete[0]

        # Compare with expected URL:
        self.assertIn('index=111',passed_url,
            'The index 111 is not specified in the URL '+passed_url+'. This may be serious!')
        self.assertNotIn('&index=',passed_url,
            'A second index was specified in the URL '+passed_url+'. This may be serious!')

    @patch('b2handle.handleclient.requests.delete')
    @patch('b2handle.handleclient.requests.get')
    def test_delete_handle_value_several_occurrences(self, getpatch, deletepatch):
        """Test trying to delete from a corrupted handle record."""

        # Define the replacement for the patched GET method (getting a corrupted record):
        cont = {"responseCode":1,"handle":"my/testhandle","values":[{"index":111,"type":"test1","data":{"format":"string","value":"val1"},"ttl":86400,"timestamp":"2015-09-30T15:08:49Z"},{"index":2222,"type":"test2","data":{"format":"string","value":"val2"},"ttl":86400,"timestamp":"2015-09-30T15:08:49Z"},{"index":333,"type":"test2","data":{"format":"string","value":"val3"},"ttl":86400,"timestamp":"2015-09-30T15:08:49Z"},{"index":4,"type":"test4","data":{"format":"string","value":"val4"},"ttl":86400,"timestamp":"2015-09-30T15:08:49Z"}]}
        mock_response_get = MockResponse(status_code=200, content=json.dumps(cont))
        getpatch.return_value = mock_response_get

        # Define the replacement for the patched requests.delete method:
        mock_response_del = MockResponse()
        deletepatch.return_value = mock_response_del

        # Call the method to be tested:
        self.inst.delete_handle_value('my/testhandle', 'test2')

        # Get the args passed to "requests.delete"
        # For help, please see: http://www.voidspace.org.uk/python/mock/examples.html#checking-multiple-calls-with-mock
        positional_args_passed_to_delete = deletepatch.call_args_list[len(deletepatch.call_args_list)-1][0]
        passed_url = positional_args_passed_to_delete[0]

        # Compare with expected URL:
        self.assertIn('index=2222',passed_url,
            'The index 2222 is not specified in the URL '+passed_url+'. This may be serious!')
        self.assertIn('index=333',passed_url,
            'The index 333 is not specified in the URL '+passed_url+'. This may be serious!')

        # Check if PUT was called once:
        self.assertEqual(deletepatch.call_count, 1,
            'The method "requests.put" was not called once, but '+str(deletepatch.call_count)+' times.')

    # delete_handle:

    @patch('b2handle.handleclient.requests.delete')
    def test_delete_handle(self, deletepatch):

        # Define the replacement for the patched requests.delete method:
        mock_response_del = MockResponse(success=True)
        deletepatch.return_value = mock_response_del

        # Call method to be tested:
        self.inst.delete_handle('my/testhandle')

        # Get the args passed to "requests.delete"
        # For help, please see: http://www.voidspace.org.uk/python/mock/examples.html#checking-multiple-calls-with-mock
        positional_args_passed_to_delete = deletepatch.call_args_list[len(deletepatch.call_args_list)-1][0]
        passed_url = positional_args_passed_to_delete[0]

        # Compare with expected URL:
        self.assertNotIn('index=',passed_url,
            'Indices were passed to the delete method.')

    @patch('b2handle.handleclient.requests.delete')
    @patch('b2handle.handleclient.requests.get')
    def test_delete_handle_inexistent(self, getpatch, deletepatch):

        # Define the replacement for the patched GET method:
        mock_response_get = MockResponse(notfound=True)
        getpatch.return_value = mock_response_get

        # Define the replacement for the patched requests.delete method:
        mock_response_del = MockResponse(notfound=True)
        deletepatch.return_value = mock_response_del

        # Call method to be tested:
        resp = self.inst.delete_handle('my/testhandle')

        # Check if response is ok:
        self.assertIsNone(resp,
            'The response code when deleting inexistent handle should be None but is: '+str(resp))

    def test_delete_handle_too_many_args(self):

        # Call method to be tested:
        with self.assertRaises(TypeError):
            self.inst.delete_handle('my/testhandle', 'test1')

    # 10320/LOC

    # remove_additional_URL

    @patch('b2handle.handleclient.requests.put')
    @patch('b2handle.handleclient.requests.get')
    def test_remove_additional_URL(self, getpatch, putpatch):
        """Test normal removal of additional URL from 10320/LOC."""

        # Define the replacement for the patched GET method:
        cont = {"responseCode":1,"handle":"my/testhandle","values":[{"index":1,"type":"URL","data":{"format":"string","value":"www.url.foo"},"ttl":86400,"timestamp":"2015-09-30T15:54:32Z"},{"index":2,"type":"10320/LOC","data":{"format":"string","value":"<locations><location href = 'http://first.foo' /><location href = 'http://second.foo' /></locations> "},"ttl":86400,"timestamp":"2015-09-30T15:54:32Z"}]}
        mock_response_get = MockResponse(status_code=200, content=json.dumps(cont))
        getpatch.return_value = mock_response_get

        # Define the replacement for the patched requests.put method:
        cont = {"responseCode":1,"handle":"my/testhandle"}
        mock_response_put = MockResponse(status_code=200, content=json.dumps(cont))
        putpatch.return_value = mock_response_put

        # Run the method to be tested:
        testhandle = 'my/testhandle'
        url = 'http://first.foo'
        self.inst.remove_additional_URL(testhandle, url)

        # Check if the PUT request was sent exactly once:
        self.assertEqual(putpatch.call_count, 1,
            'The method "requests.put" was not called once, but '+str(putpatch.call_count)+' times.')

        # Get the payload passed to "requests.put"
        # For help, please see: http://www.voidspace.org.uk/python/mock/examples.html#checking-multiple-calls-with-mock
        passed_payload, _ = self.get_payload_headers_from_mockresponse(putpatch)

        # Compare with expected payload:
        expected_payload = {"values": [{"index": 1, "ttl": 86400, "type": "URL", "timestamp": "2015-09-30T15:54:32Z", "data": {"value": "www.url.foo", "format": "string"}}, {"index": 2, "ttl": 86400, "type": "10320/LOC", "timestamp": "2015-09-30T15:54:32Z", "data": {"value": "<locations><location href=\"http://second.foo\" /></locations>", "format": "string"}}]}
        replace_timestamps(expected_payload)
        self.assertEqual(passed_payload, expected_payload,
            failure_message(expected=expected_payload,
                                 passed=passed_payload,
                                 methodname='remove_additional_URL'))

    @patch('b2handle.handleclient.requests.put')
    @patch('b2handle.handleclient.requests.get')
    def test_remove_additional_URL_toempty(self, getpatch, putpatch):
        """Test removing all URL, which should remove the whole 10320/LOC attribute."""

        # Define the replacement for the patched GET method (a record with one additional URL in it):
        cont = {"responseCode":1,"handle":"my/testhandle","values":[{"index":1,"type":"URL","data":{"format":"string","value":"www.url.foo"},"ttl":86400,"timestamp":"2015-09-30T15:54:33Z"},{"index":2,"type":"10320/LOC","data":{"format":"string","value":"<locations><location href=\"http://second.foo\" /></locations>"},"ttl":86400,"timestamp":"2015-09-30T15:54:33Z"}]}
        mock_response_get = MockResponse(status_code=200, content=json.dumps(cont))
        getpatch.return_value = mock_response_get

        # Define the replacement for the patched requests.put method:
        cont = {"responseCode":1,"handle":"my/testhandle"}
        mock_response_put = MockResponse(status_code=200, content=json.dumps(cont))
        putpatch.return_value = mock_response_put

        # Run the method to be tested:
        testhandle = 'my/testhandle'
        url2 = 'http://second.foo'
        self.inst.remove_additional_URL(testhandle, url2)

        # Check if the PUT request was sent exactly once:
        self.assertEqual(putpatch.call_count, 1,
            'The method "requests.put" was not called once, but '+str(putpatch.call_count)+' times.')

        # Get the payload passed to "requests.put"
        passed_payload, _ = self.get_payload_headers_from_mockresponse(putpatch)

        # Compare with expected payload:
        expected_payload = {"values": [{"index": 1, "ttl": 86400, "type": "URL", "timestamp": "2015-09-30T15:54:33Z", "data": {"value": "www.url.foo", "format": "string"}}]}
        replace_timestamps(expected_payload)
        self.assertEqual(passed_payload, expected_payload,
            failure_message(expected=expected_payload,
                                 passed=passed_payload,
                                 methodname='remove_additional_URL'))

    @patch('b2handle.handleclient.requests.put')
    @patch('b2handle.handleclient.requests.get')
    def test_remove_additional_URL_several(self, getpatch, putpatch):
        """Test removing all URL at the same time, which should remove the whole 10320/LOC attribute."""

        # Test variables
        testhandle = 'my/testhandle'
        url1 =  'http://first.foo'
        url2 = 'http://second.foo'

        # Define the replacement for the patched GET method:
        cont = {"responseCode":1,"handle":testhandle,"values":[{"index":1,"type":"URL","data":{"format":"string","value":"www.url.foo"},"ttl":86400,"timestamp":"2015-09-30T15:54:32Z"},{"index":2,"type":"10320/LOC","data":{"format":"string","value":"<locations><location href = 'http://first.foo' /><location href = 'http://second.foo' /></locations> "},"ttl":86400,"timestamp":"2015-09-30T15:54:32Z"}]}
        mock_response_get = MockResponse(status_code=200, content=json.dumps(cont))
        getpatch.return_value = mock_response_get

        # Define the replacement for the patched requests.put method:
        cont = {"responseCode":1,"handle":testhandle}
        mock_response_put = MockResponse(status_code=200, content=json.dumps(cont))
        putpatch.return_value = mock_response_put

        # Run code to be tested:
        self.inst.remove_additional_URL(testhandle, url1, url2)

        # Check if the PUT request was sent exactly once:
        self.assertEqual(putpatch.call_count, 1,
            'The method "requests.put" was not called once, but '+str(putpatch.call_count)+' times.')

        # Get the payload passed to "requests.put"
        # For help, please see: http://www.voidspace.org.uk/python/mock/examples.html#checking-multiple-calls-with-mock
        passed_payload, _ = self.get_payload_headers_from_mockresponse(putpatch)

        # Compare with expected payload:
        expected_payload = {"values": [{"index": 1, "ttl": 86400, "type": "URL", "timestamp": "2015-09-30T15:54:32Z", "data": {"value": "www.url.foo", "format": "string"}}]}
        replace_timestamps(expected_payload)

        self.assertEqual(passed_payload, expected_payload,
            failure_message(expected=expected_payload,
                                 passed=passed_payload,
                                 methodname='remove_additional_URL'))

    @patch('b2handle.handleclient.requests.put')
    @patch('b2handle.handleclient.requests.get')
    def test_remove_additional_URL_inexistent_handle(self, getpatch, putpatch):
        """Test normal removal of additional URL from an inexistent handle."""

        # Test variables
        testhandle = 'my/testhandle'
        url = 'http://first.foo'

        # Define the replacement for the patched GET method:
        mock_response_get = MockResponse(notfound=True)
        getpatch.return_value = mock_response_get

        # Define the replacement for the patched requests.put method:
        mock_response_put = MockResponse(notfound=True)
        putpatch.return_value = mock_response_put

        # Run code to be tested + check exception:
        with self.assertRaises(HandleNotFoundException):
            self.inst.remove_additional_URL(testhandle, url)

    
    # exchange_additional_URL

    @patch('b2handle.handleclient.requests.put')
    @patch('b2handle.handleclient.requests.get')
    def test_exchange_additional_URL_normal(self, getpatch, putpatch):
        """Test replacing an URL."""

        # Define the replacement for the patched GET method:
        cont = {"responseCode":1,"handle":"my/testhandle","values":[{"index":1,"type":"URL","data":{"format":"string","value":"www.url.foo"},"ttl":86400,"timestamp":"2015-09-30T15:54:32Z"},{"index":2,"type":"10320/LOC","data":{"format":"string","value":"<locations><location href = 'http://first.foo' /><location href = 'http://second.foo' /></locations> "},"ttl":86400,"timestamp":"2015-09-30T15:54:32Z"}]}
        mock_response_get = MockResponse(status_code=200, content=json.dumps(cont))
        getpatch.return_value = mock_response_get

        # Define the replacement for the patched requests.put method:
        cont = {"responseCode":1,"handle":"my/testhandle"}
        mock_response_put = MockResponse(status_code=200, content=json.dumps(cont))
        putpatch.return_value = mock_response_put

        # Run the method to be tested:
        old = 'http://first.foo'
        new = 'http://newfirst.foo'
        self.inst.exchange_additional_URL(
            'my/testhandle',
            old, new)

        # Check if the PUT request was sent exactly once:
        self.assertEqual(putpatch.call_count, 1,
            'The method "requests.put" was not called once, but '+str(putpatch.call_count)+' times.')

        # Get the payload passed to "requests.put"
        passed_payload, _ = self.get_payload_headers_from_mockresponse(putpatch)

        # Compare with expected payload:
        expected_payload = {"values": [{"index": 1, "ttl": 86400, "type": "URL", "timestamp": "2015-09-30T15:54:32Z", "data": {"value": "www.url.foo", "format": "string"}}, {"index": 2, "ttl": 86400, "type": "10320/LOC", "timestamp": "2015-09-30T15:54:32Z", "data": {"value": "<locations><location href=\"http://newfirst.foo\" /><location href=\"http://second.foo\" /></locations>", "format": "string"}}]}
        replace_timestamps(expected_payload)
        self.assertEqual(passed_payload, expected_payload,
            failure_message(expected=expected_payload,
                                 passed=passed_payload,
                                 methodname='exchange_additional_URL'))

    @patch('b2handle.handleclient.requests.put')
    @patch('b2handle.handleclient.requests.get')
    def test_exchange_additional_URL_doesnotexist(self, getpatch, putpatch):
        """Test if replacing an inexistent URL has any effect."""

        # Define the replacement for the patched GET method:
        cont = {"responseCode":1,"handle":"my/testhandle","values":[{"index":1,"type":"URL","data":{"format":"string","value":"www.url.foo"},"ttl":86400,"timestamp":"2015-09-30T15:54:32Z"},{"index":2,"type":"10320/LOC","data":{"format":"string","value":"<locations><location href = 'http://first.foo' /><location href = 'http://second.foo' /></locations> "},"ttl":86400,"timestamp":"2015-09-30T15:54:32Z"}]}
        mock_response_get = MockResponse(status_code=200, content=json.dumps(cont))
        getpatch.return_value = mock_response_get

        # Define the replacement for the patched requests.put method:
        cont = {"responseCode":1,"handle":"my/testhandle"}
        mock_response_put = MockResponse(status_code=200, content=json.dumps(cont))
        putpatch.return_value = mock_response_put

        # Run the method to be tested:
        inexistent_old = 'http://sodohfasdkfjhanwikfhbawkedfhbawe.foo'
        new = 'http://newfirst.foo'
        self.inst.exchange_additional_URL(
            'my/testhandle',
            inexistent_old, new)

        # Check if the PUT request was sent:
        self.assertEqual(putpatch.call_count, 0,
            'The method "requests.put" was called '+str(putpatch.call_count)+' times - it should not be called at all.')

    @patch('b2handle.handleclient.requests.put')
    @patch('b2handle.handleclient.requests.get')
    def test_exchange_additional_URL_no10320loc(self, getpatch, putpatch):
        """Test if replacing an URL has any effect if there is no 10320/LOC."""

        # Define the replacement for the patched GET method:
        cont = {"responseCode":1,"handle":"my/testhandle","values":[{"index":1,"type":"URL","data":{"format":"string","value":"www.url.foo"},"ttl":86400,"timestamp":"2015-09-30T15:54:32Z"}]}
        mock_response_get = MockResponse(status_code=200, content=json.dumps(cont))
        getpatch.return_value = mock_response_get

        # Define the replacement for the patched requests.put method:
        cont = {"responseCode":1,"handle":"my/testhandle"}
        mock_response_put = MockResponse(status_code=200, content=json.dumps(cont))
        putpatch.return_value = mock_response_put

        # Run the method to be tested:
        old = 'http://first.foo'
        new = 'http://newfirst.foo'
        self.inst.exchange_additional_URL(
            'my/testhandle',
            old, new)

        # Check if the PUT request was sent:
        self.assertEqual(putpatch.call_count, 0,
            'The method "requests.put" was called '+str(putpatch.call_count)+' times - it should not be called at all.')

    # add_additional_URL

    @patch('b2handle.handleclient.requests.put')
    @patch('b2handle.handleclient.requests.get')
    def test_add_additional_URL_first(self, getpatch, putpatch):
        """Test adding the first additional URL'(created the 10320/LOC entry)."""

        # Define the replacement for the patched GET method:
        cont = {"responseCode":1,"handle":"my/testhandle","values":[{"index":1,"type":"URL","data":{"format":"string","value":"www.url.foo"},"ttl":86400,"timestamp":"2015-09-30T15:54:32Z"}]}
        mock_response_get = MockResponse(status_code=200, content=json.dumps(cont))
        getpatch.return_value = mock_response_get

        # Define the replacement for the patched requests.put method:
        cont = {"responseCode":1,"handle":"my/testhandle"}
        mock_response_put = MockResponse(status_code=200, content=json.dumps(cont))
        putpatch.return_value = mock_response_put

        # Run the method to be tested:
        url = 'http://first.foo'
        self.inst.add_additional_URL('my/testhandle', url)

        # Check if the PUT request was sent exactly once:
        self.assertEqual(putpatch.call_count, 1,
            'The method "requests.put" was not called once, but '+str(putpatch.call_count)+' times.')

        # Get the payload+headers passed to "requests.put"
        passed_payload, _ = self.get_payload_headers_from_mockresponse(putpatch)

        # Compare with expected payload:
        expected_payload = {"values": [{"index": 1, "ttl": 86400, "type": "URL", "timestamp": "2015-09-30T15:54:30Z", "data": {"value": "www.url.foo", "format": "string"}}, {"index": 2, "type": "10320/LOC", "data": "<locations><location href=\"http://first.foo\" id=\"0\" /></locations>"}]}
        replace_timestamps(expected_payload)        
        self.assertEqual(passed_payload, expected_payload,
            failure_message(expected=expected_payload, passed=passed_payload, methodname='add_additional_URL'))

    @patch('b2handle.handleclient.requests.put')
    @patch('b2handle.handleclient.requests.get')
    def test_add_additional_URL_another(self, getpatch, putpatch):
        """Test adding an additional URL."""

        # Define the replacement for the patched GET method:
        cont = {"responseCode":1,"handle":"my/testhandle","values":[{"index":1,"type":"URL","data":{"format":"string","value":"www.url.foo"},"ttl":86400,"timestamp":"2015-09-30T15:54:30Z"},{"index":2,"type":"10320/LOC","data":{"format":"string","value":"<locations><location href = 'http://first.foo' /><location href = 'http://second.foo' /></locations> "},"ttl":86400,"timestamp":"2015-09-30T15:54:30Z"}]}
        mock_response_get = MockResponse(status_code=200, content=json.dumps(cont))
        getpatch.return_value = mock_response_get

        # Define the replacement for the patched requests.put method:
        cont = {"responseCode":1,"handle":"my/testhandle"}
        mock_response_put = MockResponse(status_code=200, content=json.dumps(cont))
        putpatch.return_value = mock_response_put

        # Run the method to be tested:
        url = 'http://third.foo'
        self.inst.add_additional_URL('my/testhandle', url)

        # Get the payload+headers passed to "requests.put"
        passed_payload, _ = self.get_payload_headers_from_mockresponse(putpatch)

        # Compare with expected payload:
        expected_payload = {"values": [{"index": 1, "ttl": 86400, "type": "URL", "timestamp": "2015-09-30T15:54:30Z", "data": {"value": "www.url.foo", "format": "string"}}, {"index": 2, "ttl": 86400, "type": "10320/LOC", "timestamp": "2015-09-30T15:54:30Z", "data": "<locations><location href=\"http://first.foo\" /><location href=\"http://second.foo\" /><location href=\"http://third.foo\" id=\"0\" /></locations>"}]}
        replace_timestamps(expected_payload)
        self.assertEqual(passed_payload, expected_payload,
            failure_message(expected=expected_payload, passed=passed_payload, methodname='add_additional_URL'))

    @patch('b2handle.handleclient.requests.put')
    @patch('b2handle.handleclient.requests.get')
    def test_add_additional_URL_several(self, getpatch, putpatch):
        """Test adding several (3) additional URLs."""

        # Define the replacement for the patched GET method:
        cont = {
            "responseCode":1,"handle":"my/testhandle",
            "values":[
            {
                "index":1,
                "type":"URL",
                "data":{
                    "format":"string",
                    "value":"www.url.foo"
                },"ttl":86400,
                "timestamp":"2015-09-30T15:54:31Z"
            },{
                "index":2,
                "type":"10320/LOC",
                "data":{
                    "format":"string",
                    "value":"<locations><location href = 'http://first.foo' /><location href = 'http://second.foo' /></locations> "
                }, "ttl":86400,"timestamp":"2015-09-30T15:54:31Z"
            }
            ]
        }
        mock_response_get = MockResponse(status_code=200, content=json.dumps(cont))
        getpatch.return_value = mock_response_get

        # Define the replacement for the patched requests.put method:
        cont = {"responseCode":1,"handle":"my/testhandle"}
        mock_response_put = MockResponse(status_code=200, content=json.dumps(cont))
        putpatch.return_value = mock_response_put

        # Run the method to be tested:
        url1 = 'http://one'
        url2 = 'http://two'
        url3 = 'http://three'
        self.inst.add_additional_URL('my/testhandle', url1, url2, url3)

        # Get the payload+headers passed to "requests.put"
        passed_payload, _ = self.get_payload_headers_from_mockresponse(putpatch)

        # Compare with expected payload:
        expected_payload = {"values": [{"index": 1, "ttl": 86400, "type": "URL", "timestamp": "2015-09-30T15:54:31Z", "data": {"value": "www.url.foo", "format": "string"}}, {"index": 2, "ttl": 86400, "type": "10320/LOC", "timestamp": "2015-09-30T15:54:31Z", "data": "<locations><location href=\"http://first.foo\" /><location href=\"http://second.foo\" /><location href=\"http://one\" id=\"0\" /><location href=\"http://two\" id=\"1\" /><location href=\"http://three\" id=\"2\" /></locations>"}]}
        replace_timestamps(expected_payload)        
        self.assertEqual(passed_payload, expected_payload,
            failure_message(expected=expected_payload, passed=passed_payload, methodname='add_additional_URL'))

    @patch('b2handle.handleclient.requests.put')
    @patch('b2handle.handleclient.requests.get')
    def test_add_additional_URL_to_inexistent_handle(self, getpatch, putpatch):
        """Test exception if handle does not exist."""

        # Define the replacement for the patched GET method:
        mock_response_get = MockResponse(notfound=True)
        getpatch.return_value = mock_response_get

        # Define the replacement for the patched requests.put method:
        mock_response_put = MockResponse()
        putpatch.return_value = mock_response_put

        # Run the method to be tested:
        url = 'http://first.foo'
        with self.assertRaises(HandleNotFoundException):
            self.inst.add_additional_URL('my/testhandle', url)

        # Check if the PUT request was sent:
        self.assertEqual(putpatch.call_count, 0,
            'The method "requests.put" was called '+str(putpatch.call_count)+' times - it should not be called at all.')

    @patch('b2handle.handleclient.requests.put')
    @patch('b2handle.handleclient.requests.get')
    def test_add_additional_URL_alreadythere(self, getpatch, putpatch):
        """Test adding an URL that is already there."""

        # Define the replacement for the patched GET method:
        cont = {"responseCode":1,"handle":"my/testhandle","values":[{"index":1,"type":"URL","data":{"format":"string","value":"www.url.foo"},"ttl":86400,"timestamp":"2015-09-30T15:54:30Z"},{"index":2,"type":"10320/LOC","data":{"format":"string","value":"<locations><location href = 'http://first.foo' /><location href = 'http://second.foo' /></locations> "},"ttl":86400,"timestamp":"2015-09-30T15:54:30Z"}]}
        mock_response_get = MockResponse(status_code=200, content=json.dumps(cont))
        getpatch.return_value = mock_response_get

        # Define the replacement for the patched requests.put method:
        cont = {"responseCode":1,"handle":"my/testhandle"}
        mock_response_put = MockResponse(status_code=200, content=json.dumps(cont))
        putpatch.return_value = mock_response_put

        # Run the method to be tested:
        url = 'http://first.foo'
        self.inst.add_additional_URL('my/testhandle', url)

        # Check if the PUT request was sent exactly once:
        self.assertEqual(putpatch.call_count, 0,
            'The method "requests.put" was called '+str(putpatch.call_count)+' times (should be 0).')

    @patch('b2handle.handleclient.requests.put')
    @patch('b2handle.handleclient.requests.get')
    def test_GenericHandleError(self, getpatch, putpatch):
        """Test causing a Generic Handle Exception.

        This should never happen, but this exception was designed for the
        really unexpected things, so to make sure it works, I invent a
        ver broken illegal action here.
        """

        # Define the replacement for the patched GET method:
        cont = {"responseCode":1,"handle":"not/me","values":[{"index":1,"type":"URL","data":{"format":"string","value":"www.url.foo"},"ttl":86400,"timestamp":"2015-09-30T15:54:30Z"},{"index":2,"type":"10320/LOC","data":{"format":"string","value":"<locations><location href = 'http://first.foo' /><location href = 'http://second.foo' /></locations> "},"ttl":86400,"timestamp":"2015-09-30T15:54:30Z"}]}
        mock_response_get = MockResponse(status_code=200, content=json.dumps(cont))
        getpatch.return_value = mock_response_get

        # Define the replacement for the patched requests.put method:
        mock_response_put = MockResponse()
        putpatch.return_value = mock_response_put

        # Run the method to be tested:
        with self.assertRaises(GenericHandleError):
            self.inst.retrieve_handle_record_json('my/testhandle')

        # Check if the PUT request was sent exactly once:
        self.assertEqual(putpatch.call_count, 0,
            'The method "requests.put" was called '+str(putpatch.call_count)+' times. It should not have been called at all.')


    @patch('b2handle.handleclient.requests.put')
    @patch('b2handle.handleclient.requests.get')
    def test_add_additional_URL_several_toempty(self, getpatch, putpatch):
        """Test adding several (3) additional URLs to a handle that has no 10320/LOC."""

        # Test variables
        testhandle = 'my/testhandle'
        url1 = 'http://one'
        url2 = 'http://two'
        url3 = 'http://three'

        # Define the replacement for the patched GET method:
        cont = {
            "responseCode":1,
            "handle":testhandle,
            "values":[
            {
                "index":1,
                "type":"URL",
                "data":{
                    "format":"string",
                    "value":"www.url.foo"
                },
                "ttl":86400,
                "timestamp":"2015-09-30T15:54:31Z"
            }
            ]
        }
        mock_response_get = MockResponse(status_code=200, content=json.dumps(cont))
        getpatch.return_value = mock_response_get

        # Define the replacement for the patched requests.put method:
        cont = {"responseCode":1,"handle":testhandle}
        mock_response_put = MockResponse(status_code=200, content=json.dumps(cont))
        putpatch.return_value = mock_response_put

        # Run code to be tested:
        self.inst.add_additional_URL(testhandle, url1, url2, url3)

        # Get the payload+headers passed to "requests.put"
        passed_payload, _ = self.get_payload_headers_from_mockresponse(putpatch)

        # Compare with expected payload:
        expected_payload = {"values": [{"index": 1, "ttl": 86400, "type": "URL", "timestamp": "2015-09-30T15:54:31Z", "data": {"value": "www.url.foo", "format": "string"}}, {"index": 2, "type": "10320/LOC", "timestamp": "2015-09-30T15:54:31Z", "data": "<locations><location href=\"http://one\" id=\"0\" /><location href=\"http://two\" id=\"1\" /><location href=\"http://three\" id=\"2\" /></locations>"}]}
        replace_timestamps(expected_payload)        
        self.assertEqual(passed_payload, expected_payload,
            failure_message(expected=expected_payload, passed=passed_payload, methodname='add_additional_URL'))

    # search_handle

    @patch('b2handle.handleclient.requests.get')
    @patch('b2handle.handleclient.EUDATHandleClient.check_if_username_exists')
    def test_search_handle_wrong_url(self, usernamepatch, getpatch):
        """Test exception when wrong search servlet URL is given."""

        # Define the replacement for the patched check_if_username_exists method:
        mock_response_user = MockResponse(success=True)
        usernamepatch.return_value = mock_response_user

        # Define the replacement for the patched GET method:
        mock_response_get = MockSearchResponse(wrong_url=True)
        getpatch.return_value = mock_response_get
        
        # Setup client for searching with existent but wrong url (google.com):
        inst = EUDATHandleClient.instantiate_with_username_and_password(
            "url_https",
            "100:user/name",
            "password",
            reverselookup_baseuri='http://www.google.com',
            HTTP_verify=True)

        # Run code to be tested + check exception:
        with self.assertRaises(ReverseLookupException):
            self.inst.search_handle(URL='*')

    @patch('b2handle.handleclient.requests.get')
    @patch('b2handle.handleclient.EUDATHandleClient.check_if_username_exists')
    def test_search_handle_handleurl(self, usernamepatch, getpatch):
        """Test exception when wrong search servlet URL (Handle Server REST API URL) is given."""

        # Define the replacement for the patched check_if_username_exists method:
        mock_response_user = MockResponse(success=True)
        usernamepatch.return_value = mock_response_user

        # Define the replacement for the patched GET method:
        mock_response_search = MockSearchResponse(handle_url=True)
        getpatch.return_value = mock_response_search

        # Setup client for searching with Handle Server url:
        inst = EUDATHandleClient.instantiate_with_username_and_password(
            "url_https",
            "100:user/name",
            "password",
            reverselookup_url_extension='/api/handles/',
            HTTP_verify=True)

        # Run code to be tested + check exception:
        with self.assertRaises(ReverseLookupException):
            self.inst.search_handle(URL='*')

    @patch('b2handle.handleclient.requests.get')
    def test_search_handle(self, getpatch):
        """Test searching for handles with any url (server should return list of handles)."""

        # Define the replacement for the patched GET method:
        mock_response_get = MockSearchResponse(success=True)
        getpatch.return_value = mock_response_get

        # Run code to be tested:
        val = self.inst.search_handle(URL='*')

        # Check desired outcome:
        self.assertEqual(type(val),type([]),
            '')
        self.assertTrue(len(val) > 0,
            '')
        self.assertTrue(self.inst.check_handle_syntax(val[0]),
            '')

    @patch('b2handle.handleclient.requests.get')
    def test_search_handle_emptylist(self, getpatch):
        """Test empty search result."""

        # Define the replacement for the patched GET method:
        mock_response_get = MockSearchResponse(empty=True)
        getpatch.return_value = mock_response_get

        # Run code to be tested:
        val = self.inst.search_handle(URL='noturldoesnotexist')

        # Check desired outcome:
        self.assertEqual(type(val),type([]),
            '')
        self.assertEqual(len(val),0,
            '')

    @patch('b2handle.handleclient.requests.get')
    def test_search_handle_for_url(self, getpatch):
        """Test searching for url with wildcards."""

        # Define the replacement for the patched GET method:
        mock_response_get = MockSearchResponse(success=True)
        getpatch.return_value = mock_response_get

        # Run code to be tested:
        val = self.inst.search_handle(URL='*dkrz*')

        # Check desired outcome:
        self.assertEqual(type(val),type([]),
            '')

        # Run code to be tested:
        val = self.inst.search_handle('*dkrz*')

        # Check desired outcome:
        self.assertEqual(type(val),type([]),
            '')

    if False:
        # At the moment, two keywords can not be searched!
        @patch('b2handle.handleclient.requests.get')
        def test_search_handle_for_url_and_checksum(self, getpatch):
            """Test searching for url and checksum with wildcards."""

            # Define the replacement for the patched GET method:
            mock_response_get = MockSearchResponse(success=True)
            getpatch.return_value = mock_response_get

            # Run code to be tested:
            val = self.inst.search_handle('*dkrz*', CHECKSUM='*123*')

            # Check desired outcome:
            self.assertEqual(type(val),type([]),
                '')

            # Run code to be tested:
            val = self.inst.search_handle(URL='*dkrz*', CHECKSUM='*123*')

            # Check desired outcome:
            self.assertEqual(type(val),type([]),
                '')

    @patch('b2handle.handleclient.requests.get')
    def test_search_handle_prefixfilter(self, getpatch):
        """Test filtering for prefixes."""

        prefix = "11111"

        # Define the replacement for the patched GET method:
        mock_response_get = MockSearchResponse(prefix=prefix)
        getpatch.return_value = mock_response_get

        # Run code to be tested:
        val = self.inst.search_handle(URL='*dkrz*', prefix=prefix)

        # Check desired outcome:
        self.assertEqual(type(val),type([]),
            '')
        for item in val:
            self.assertEqual(item.split('/')[0], prefix)

    @patch('b2handle.handleclient.requests.get')
    def test_search_handle_prefixfilter_realprefix(self, getpatch):
        """Test filtering for prefixes."""

        prefix = "10876.test"

        # Define the replacement for the patched GET method:
        mock_response_get = MockSearchResponse(prefix=prefix)
        getpatch.return_value = mock_response_get

        # Run code to be tested:
        val = self.inst.search_handle(URL='*dkrz*', prefix=prefix)

        # Check desired outcome:
        self.assertEqual(type(val),type([]),
            '')
        for item in val:
            self.assertEqual(item.split('/')[0], prefix)

    @patch('b2handle.handleclient.requests.get')
    def test_search_handle_fulltext(self, getpatch):
        """Test filtering for prefixes."""

        prefix = "10876.test"

        # Define the replacement for the patched GET method:
        mock_response_get = MockSearchResponse(prefix=prefix)
        getpatch.return_value = mock_response_get

        # Run code to be tested + check exception:
        with self.assertRaises(ReverseLookupException):
            self.inst.search_handle(URL='*dkrz*', searchterms=['foo','bar'])

