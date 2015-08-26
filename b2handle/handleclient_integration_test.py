import unittest
from b2handle.handleclient import EUDATHandleClient
import b2handle.clientcredentials
from b2handle.handleexceptions import HandleSyntaxError
from b2handle.handleexceptions import HandleNotFoundException
from b2handle.handleexceptions import GenericHandleError
from b2handle.handleexceptions import HandleAlreadyExistsException
from b2handle.handleexceptions import BrokenHandleRecordException
from b2handle.handleexceptions import ReverseLookupException
import logging
import requests
import json

LOGGER = logging.getLogger(__name__)
LOGGER.addHandler(logging.NullHandler())

TESTVALUES = json.load(open('tests/resources/testvalues_for_integration_tests_IGNORE.json'))

class EUDATHandleClient_writeaccess_test(unittest.TestCase):

    def setUp(self):
        self.inst = EUDATHandleClient.instantiate_with_username_and_password(TESTVALUES['url_https'], TESTVALUES['user'], TESTVALUES['password'], HTTP_verify=TESTVALUES['HTTP_verify'])

        # Use this handle for testing handle creation:
        self.newhandle = TESTVALUES['handle_to_be_created']
        # Use this for modifying:
        self.handle = TESTVALUES['handle_to_be_modified']
        list_of_all_entries = [
            {
                "index":111,
                "type":"test1",
                "data":{
                    "format":"string",
                    "value":"val1"
                }
            },
            {
                "index":2222,
                "type":"test2",
                "data":{
                    "format":"string",
                    "value":"val2"
                }
            },
            {
                "index":333,
                "type":"test3",
                "data":{
                    "format":"string",
                    "value":"val3"
                }
            },
            {
                "index":4,
                "type":"test4",
                "data":{
                    "format":"string",
                    "value":"val4"
                }
            },
        ]
        url = self.inst.make_handle_URL(self.handle)
        data = json.dumps({'values':list_of_all_entries})
        headers = {'Content-Type': 'application/json', 'Authorization': 'Basic ' + self.inst.create_authentication_string(TESTVALUES['user'], TESTVALUES['password'])}
        requests.put(url, data=data, headers=headers, verify=False)

    if True:
        def modify_handle_value_corrupted_test(self):
            # Create corrupted:
            list_of_all_entries = [
                {
                    "index":111,
                    "type":"test1",
                    "data":{
                        "format":"string",
                        "value":"val1"
                    }
                },
                {
                    "index":2222,
                    "type":"test2",
                    "data":{
                        "format":"string",
                        "value":"val2"
                    }
                },
                {
                    "index":333,
                    "type":"test2",
                    "data":{
                        "format":"string",
                        "value":"val3"
                    }
                },
                {
                    "index":4,
                    "type":"test4",
                    "data":{
                        "format":"string",
                        "value":"val4"
                    }
                }
            ]
            url = self.inst.make_handle_URL(self.handle)
            data = json.dumps({'values':list_of_all_entries})
            headers = {'Content-Type': 'application/json', 'Authorization': 'Basic ' + self.inst.create_authentication_string(TESTVALUES['user'], TESTVALUES['password'])}
            requests.put(url, data=data, headers=headers, verify=False)
            # Modifying corrupted raises exception:
            self.assertRaises(BrokenHandleRecordException, self.inst.modify_handle_value, self.handle, test4='new4', test2='new2', test3='new3')

    if True:
        def modify_handle_value_severalpairs_test(self):
            handle = self.handle
            self.inst.modify_handle_value(handle, test4='new4', test2='new2', test3='new3')
            # check if modified:
            rec = self.inst.retrieve_handle_record_json(handle)
            print str(rec)
            val = self.inst.get_value_from_handle(handle, 'test4', rec)
            assert val == 'new4'
            # check if others still there:
            val = self.inst.get_value_from_handle(handle, 'test1', rec)
            assert val == 'val1'
            val = self.inst.get_value_from_handle(handle, 'test2', rec)
            assert val == 'new2'
            # check if created:
            val = self.inst.get_value_from_handle(handle, 'test3', rec)
            assert val == 'new3'

    if True:
        def modify_handle_value_test(self):
            handle = self.handle
            self.inst.modify_handle_value(handle, test4='newvalue')
            # check if modified:
            rec = self.inst.retrieve_handle_record_json(handle)
            val = self.inst.get_value_from_handle(handle, 'test4', rec)
            assert val == 'newvalue'
            # check if others still there:
            val = self.inst.get_value_from_handle(handle, 'test1', rec)
            assert val == 'val1'
            val = self.inst.get_value_from_handle(handle, 'test2', rec)
            assert val == 'val2'

    if True:
        def register_handle_test(self):
            handle = self.newhandle
            # Collect data:
            additional_URLs = ['http://bar.bar', 'http://foo.foo']
            # Write handle:
            handle_returned = self.inst.register_handle(handle, location='http://foo.bar', checksum='123456', additional_URLs=additional_URLs, overwrite=True, foo='foo', bar='bar')
            assert handle_returned == handle
            # Check if content was written ok:
            rec = self.inst.retrieve_handle_record_json(handle)
            val = self.inst.get_value_from_handle(handle, 'bar', rec)
            assert val == 'bar'
            val = self.inst.get_value_from_handle(handle, 'foo', rec)
            assert val == 'foo'
            val = self.inst.get_value_from_handle(handle, 'URL', rec)
            assert val == 'http://foo.bar'
            val = self.inst.get_value_from_handle(handle, 'checksum', rec)
            assert val == '123456'
            contained = self.inst.is_URL_contained_in_10320loc(handle, 'http://bar.bar', rec)
            assert contained
            contained = self.inst.is_URL_contained_in_10320loc(handle, 'http://foo.foo', rec)
            assert contained
            # Test overwrite = false:
            self.assertRaises(HandleAlreadyExistsException, self.inst.register_handle, handle, location='http://foo.bar', checksum='123456', additional_URLs=additional_URLs, overwrite=False, foo='foo', bar='bar')
            # Delete again:
            url = self.inst.make_handle_URL(handle)
            headers = {'Content-Type': 'application/json', 'Authorization': 'Basic ' + self.inst.create_authentication_string(TESTVALUES['user'], TESTVALUES['password'])}
            resp = requests.delete(url, headers=headers, verify=False)
            assert resp.status_code == 200
            rec = self.inst.retrieve_handle_record_json(handle)
            assert rec is None

    if True:
        def delete_handle_value_severalkeys_test(self):
            handle = self.handle
            self.inst.delete_handle_value(handle, ['test1', 'test2'])

            rec = self.inst.retrieve_handle_record_json(handle)
            val = self.inst.get_value_from_handle(handle, 'test1', rec)
            assert type(val) == type(None)
            indices = self.inst.get_handlerecord_indices_for_key('test1', rec['values'])
            assert len(indices) == 0
            val = self.inst.get_value_from_handle(handle, 'test2', rec)
            assert type(val) == type(None)
            indices = self.inst.get_handlerecord_indices_for_key('test2', rec['values'])
            assert len(indices) == 0
            LOGGER.debug('Handle record after deleting "test2" values: '+str(rec))

    if True:
        def delete_handle_value_test(self):
            handle = self.handle
            # Before:
            rec = self.inst.retrieve_handle_record_json(handle)
            indices = self.inst.get_handlerecord_indices_for_key('test1', rec['values'])
            assert len(indices) == 1
            assert indices[0] == 111
            indices = self.inst.get_handlerecord_indices_for_key('test2', rec['values'])
            assert len(indices) == 1
            assert 2222 in indices
            LOGGER.debug('Handle record before deleting values: '+str(rec))

            # delete existing handles value:
            self.inst.delete_handle_value(handle, 'test1')

            rec = self.inst.retrieve_handle_record_json(handle)
            val = self.inst.get_value_from_handle(handle, 'test1', rec)
            assert type(val) == type(None)
            indices = self.inst.get_handlerecord_indices_for_key('test1', rec['values'])
            assert len(indices) == 0
            LOGGER.debug('Handle record after deleting "test1" value: '+str(rec))

            # delete existing handles value (several):
            self.inst.delete_handle_value(handle, 'test2')

            rec = self.inst.retrieve_handle_record_json(handle)
            val = self.inst.get_value_from_handle(handle, 'test2', rec)
            assert type(val) == type(None)
            indices = self.inst.get_handlerecord_indices_for_key('test2', rec['values'])
            assert len(indices) == 0
            LOGGER.debug('Handle record after deleting "test2" values: '+str(rec))

            # delete nonexistent handle values:
            self.inst.delete_handle_value(handle, 'test2')

            val = self.inst.get_value_from_handle(handle, 'test2', rec)
            assert type(val) == type(None)
            indices = self.inst.get_handlerecord_indices_for_key('test2', rec['values'])
            assert len(indices) == 0
            LOGGER.debug('Handle record after deleting "test2" values: '+str(rec))

class EUDATHandleClient_solrservlet_test(unittest.TestCase):

    def setUp(self):
        self.inst = EUDATHandleClient.instantiate_with_username_and_password(TESTVALUES['url_https'], TESTVALUES['user'], TESTVALUES['password'], reverselookup_username=TESTVALUES['reverselookup_username'], reverselookup_password=TESTVALUES['reverselookup_password'], HTTP_verify=TESTVALUES['HTTP_verify'])

    if True:
        def search_handle_wrong_url_test(self):
            # Query existent but wrong url (google.com):
            self.inst = EUDATHandleClient.instantiate_with_username_and_password(TESTVALUES['url_https'], TESTVALUES['user'], TESTVALUES['password'], reverselookup_baseuri='http://www.google.com', HTTP_verify=TESTVALUES['HTTP_verify'])
            self.assertRaises(ReverseLookupException, self.inst.search_handle, url='*')
            # Query Handle Server url:
            self.inst = EUDATHandleClient.instantiate_with_username_and_password(TESTVALUES['url_https'], TESTVALUES['user'], TESTVALUES['password'], reverselookup_url_extension='/api/handles/', HTTP_verify=TESTVALUES['HTTP_verify'])
            self.assertRaises(ReverseLookupException, self.inst.search_handle, url='*')

    if True:
        def search_handle_test(self):

            print "Assuming there is handles on the server!"
            # Return value is a list containing handles.
            val = self.inst.search_handle(url='*')
            assert type(val) == type([])
            assert len(val) > 0
            assert self.inst.check_handle_syntax(val[0])

            # If URL does not exist, return empty list:
            val = self.inst.search_handle(url='noturldoesnotexist')
            assert type(val) == type([])
            assert len(val) == 0

            val = self.inst.search_handle(url='*dkrz*')
            assert type(val) == type([])
            val = self.inst.search_handle('*dkrz*')
            assert type(val) == type([])
            val = self.inst.search_handle('*dkrz*', checksum='*123*')
            assert type(val) == type([])
            val = self.inst.search_handle(url='*dkrz*', checksum='*123*')
            assert type(val) == type([])

            # Other fields than url and checksum are ignored:
            val = self.inst.search_handle(url='*dkrz*', checksum='*123*', anotherfield='xyz')
            assert type(val) == type([])
            val = self.inst.search_handle(url='*dkrz*', checksum='*123*', searchterms=['searchterm1', 'searchterm2'], anotherfield='xyz')
            assert type(val) == type([])

            # Prefix filters the handles for the prefixes:
            prefix = "11111"
            val = self.inst.search_handle(url='*dkrz*', prefix=prefix)
            assert type(val) == type([])
            for item in val:
                assert item.split('/')[0] == prefix
            prefix = "10876.test"
            val = self.inst.search_handle(url='*dkrz*', prefix=prefix)
            assert type(val) == type([])
            for item in val:
                assert item.split('/')[0] == prefix

class EUDATHandleClient_10320loc_writeaccess_test(unittest.TestCase):

    def setUp(self):
        self.inst = EUDATHandleClient.instantiate_with_username_and_password(TESTVALUES['url_https'], TESTVALUES['user'], TESTVALUES['password'], HTTP_verify=TESTVALUES['HTTP_verify'])
        list_of_all_entries_with = [
            {
                "index":1,
                "type":"URL",
                "data":"www.url.foo"
            },
            {
                "index":2,
                "type":"10320/loc",
                "data":{
                    "format":"string",
                    "value":"<locations><location href = 'http://first.foo' /><location href = 'http://second.foo' /></locations> "
                }
            }
        ]
        list_of_all_entries_without = [
            {
                "index":1,
                "type":"URL",
                "data":"www.url.foo"
            }
        ]
        url = self.inst.make_handle_URL(TESTVALUES['handle_with_10320loc'])
        data = json.dumps({'values':list_of_all_entries_with})
        headers = {'Content-Type': 'application/json', 'Authorization': 'Basic ' + self.inst.create_authentication_string(TESTVALUES['user'], TESTVALUES['password'])}
        requests.put(url, data=data, headers=headers, verify=False)

        url = self.inst.make_handle_URL(TESTVALUES['handle_without_10320loc'])
        data = json.dumps({'values':list_of_all_entries_without})
        headers = {'Content-Type': 'application/json', 'Authorization': 'Basic ' + self.inst.create_authentication_string(TESTVALUES['user'], TESTVALUES['password'])}
        requests.put(url, data=data, headers=headers, verify=False)

    if True:
        def add_additional_URL_several_test(self):
            self.inst.add_additional_URL(TESTVALUES['handle_with_10320loc'], 'http://one', 'http://two', 'http://three')
            contained = self.inst.is_URL_contained_in_10320loc(TESTVALUES['handle_with_10320loc'], 'http://one')
            assert contained
            contained = self.inst.is_URL_contained_in_10320loc(TESTVALUES['handle_with_10320loc'], 'http://two')
            assert contained
            contained = self.inst.is_URL_contained_in_10320loc(TESTVALUES['handle_with_10320loc'], 'http://three')
            assert contained

    if True:
        def add_additional_URL_nonexistinghandle_test(self):
            self.assertRaises(HandleNotFoundException, self.inst.add_additional_URL, TESTVALUES['handle_doesnotexist'], 'http://foo.foo')

    if True:
        def add_additional_URL_first_test(self):
            self.inst.add_additional_URL(TESTVALUES['handle_without_10320loc'], 'http://first.foo')
            contained = self.inst.is_URL_contained_in_10320loc(TESTVALUES['handle_without_10320loc'], 'http://first.foo')
            assert contained

    if True:
        def add_additional_URL_another_test(self):
            self.inst.add_additional_URL(TESTVALUES['handle_with_10320loc'], 'http://third.foo')
            contained = self.inst.is_URL_contained_in_10320loc(TESTVALUES['handle_with_10320loc'], 'http://third.foo')
            assert contained

    if True:
        def add_additional_URL_alreadythere_test(self):
            self.inst.add_additional_URL(TESTVALUES['handle_with_10320loc'], 'http://first.foo')
            contained = self.inst.is_URL_contained_in_10320loc(TESTVALUES['handle_with_10320loc'], 'http://first.foo')
            assert contained

    if True:
        def remove_additional_URL_test(self):
            self.inst.remove_additional_URL(TESTVALUES['handle_with_10320loc'], 'http://first.foo')
            contained = self.inst.is_URL_contained_in_10320loc(TESTVALUES['handle_with_10320loc'], 'http://first.foo')
            assert contained == False

    if True:
        def remove_additional_URL_toempty_test(self):
            self.inst.remove_additional_URL(TESTVALUES['handle_with_10320loc'], 'http://second.foo')
            self.inst.remove_additional_URL(TESTVALUES['handle_with_10320loc'], 'http://first.foo')
            isempty = self.inst.is_10320loc_empty(TESTVALUES['handle_with_10320loc'])
            assert isempty

class EUDATHandleClient_readaccess_test(unittest.TestCase):


    def setUp(self):
        self.inst = EUDATHandleClient(HTTP_verify=TESTVALUES['HTTP_verify'])

    if True:
        def retrieve_handle_record_json_test(self):
            rec = self.inst.retrieve_handle_record_json(TESTVALUES['handle_to_be_modified'])
            LOGGER.debug('The handle record as json: '+str(rec))
            assert rec['values'][2]['type'] == 'test3'
            assert rec['values'][2]['data']['value'] == 'val3'

    if True:
        def instantiate_with_username_and_password_test(self):
            randompassword = 'apsodasdjuhfsikjdfskdfj'
            # No exception if password wrong:
            EUDATHandleClient.instantiate_with_username_and_password(TESTVALUES['url_https'], TESTVALUES['user'], randompassword, HTTP_verify=TESTVALUES['HTTP_verify'])
            # Exception if index not given:
            self.assertRaises(HandleSyntaxError, EUDATHandleClient.instantiate_with_username_and_password, TESTVALUES['url_https'], TESTVALUES['user_without_index'], randompassword, HTTP_verify=TESTVALUES['HTTP_verify'])
            # Exception if username handle does not exist:
            self.assertRaises(HandleNotFoundException, EUDATHandleClient.instantiate_with_username_and_password, TESTVALUES['url_https'], TESTVALUES['nonexistent_user'], randompassword, HTTP_verify=TESTVALUES['HTTP_verify'])

    if True:
        def instantiate_with_credentials_test(self):
            randompassword = 'apsodasdjuhfsikjdfskdfj'
            # No exception if password wrong:
            credentials = b2handle.clientcredentials.PIDClientCredentials(TESTVALUES['url_https'], TESTVALUES['user'], randompassword)
            EUDATHandleClient.instantiate_with_credentials(credentials, HTTP_verify=TESTVALUES['HTTP_verify'])
            # Exception if handle does not exist:
            credentials = b2handle.clientcredentials.PIDClientCredentials(TESTVALUES['url_https'], TESTVALUES['nonexistent_user'], randompassword)
            self.assertRaises(HandleNotFoundException, EUDATHandleClient.instantiate_with_credentials, credentials, HTTP_verify=TESTVALUES['HTTP_verify'])
            # If the user name has no index, exception is already thrown in credentials creation!
            #self.assertRaises(HandleSyntaxError, b2handle.PIDClientCredentials, 'url', 'prefix/suffix', randompassword)

