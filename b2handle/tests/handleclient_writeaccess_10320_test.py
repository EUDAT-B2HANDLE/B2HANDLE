"""Testing methods that need Handle server write access"""

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


class EUDATHandleClientWriteaccess10320locTestCase(unittest.TestCase):

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
        self.password = self.testvalues['password']
        self.headers = None
        self.randompassword = 'some_random_password_shrgfgh345345'

    def setUp(self):
        self.inst = EUDATHandleClient.instantiate_with_username_and_password(
            self.url_https,
            self.user,
            self.password,
            HTTP_verify=self.verify)
        authstring = self.inst.create_authentication_string(self.user, self.password)
        self.headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Basic '+authstring
        }
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

        
        url = self.inst.make_handle_URL(self.handle_withloc)
        data = json.dumps({'values':list_of_all_entries_with})
        #requests.put(url, data=data, headers=self.headers, verify=self.verify)
        requests.put(url, data=data, headers=self.headers, verify=False)

        url = self.inst.make_handle_URL(self.handle_withoutloc)
        data = json.dumps({'values':list_of_all_entries_without})
        #requests.put(url, data=data, headers=self.headers, verify=self.verify)
        requests.put(url, data=data, headers=self.headers, verify=False)

    # Exchanging:

    def test_exchange_additional_URL_normal(self):
        """Test replacing an URL."""
        old = 'http://first.foo'
        new = 'http://newfirst.foo'

        # Precondition: URL included.
        contained = self.inst.is_URL_contained_in_10320loc(self.handle_withloc, old)
        bla = self.inst.retrieve_handle_record_json(self.handle_withloc)
        self.assertTrue(contained,
            'Precondition for test failed! The URL should be present at the start'
            ' of the test: '+str(bla))

        # Replace:
        self.inst.exchange_additional_URL(
            self.handle_withloc,
            old, new)
        contained = self.inst.is_URL_contained_in_10320loc(
            self.handle_withloc,
            new)

        # Check if was replaced (hopefully yes!):
        self.assertTrue(contained,
            'After replacing an URL, the replacement was not there.')
        # TODO Check if index was the same!!

    def test_exchange_additional_URL_doesnotexist(self):
        """Test if replacing an inexistent URL has any effect."""
        inexistent_old = 'http://sodohfasdkfjhanwikfhbawkedfhbawe.foo'
        new = 'http://newfirst.foo'

        # Precondition: URL not there yet.
        contained = self.inst.is_URL_contained_in_10320loc(
            self.handle_withloc,
            inexistent_old)
        self.assertFalse(contained,
            'Precondition for test failed! The URL should not be present at the start of the test.')

        # Replace:
        self.inst.exchange_additional_URL(
            self.handle_withloc,
            inexistent_old, new)

        # Check if was replaced (hopefully not!):
        contained = self.inst.is_URL_contained_in_10320loc(
            self.handle_withloc,
            new)
        self.assertFalse(contained,
            'After replacing a nonexistent URL, the replacement was there.')

    def test_exchange_additional_URL_no10320loc(self):
        """Test if replacing an URL has any effect if there is no 10320/loc."""
        old = 'http://first.foo'
        new = 'http://newfirst.foo'

        self.inst.exchange_additional_URL(
            self.handle_withoutloc,
            old, new)
        contained = self.inst.is_URL_contained_in_10320loc(
            self.handle_withoutloc,
            new)
        self.assertFalse(contained,
            'After replacing an URL in nonexistent 10320/loc, the replacement was there.')
    
    # Adding:

    def test_add_additional_URL_first(self):
        """Test adding the first additional URL'(created the 10320/loc entry)."""
        url = 'http://first.foo'
        self.inst.add_additional_URL(self.handle_withoutloc, url)
        contained = self.inst.is_URL_contained_in_10320loc(
            self.handle_withoutloc,
            url)
        self.assertTrue(contained,
            'The (first) URL was not added or the 10320/loc was not created.')

    def test_add_additional_URL_another(self):
        """Test adding an additional URL."""
        url = 'http://third.foo'
        self.inst.add_additional_URL(self.handle_withloc, url)
        contained = self.inst.is_URL_contained_in_10320loc(
            self.handle_withloc,
            url)
        self.assertTrue(contained,
            'The URL was not added.')

    def test_add_additional_URL_several(self):
        """Test adding several (3) additional URLs."""

        # Add URLs:
        url1 = 'http://one'
        url2 = 'http://two'
        url3 = 'http://three'
        self.inst.add_additional_URL(self.handle_withloc, url1, url2, url3)

        # Check if contained:
        contained1 = self.inst.is_URL_contained_in_10320loc(
            self.handle_withloc,
            url1)
        contained2 = self.inst.is_URL_contained_in_10320loc(
            self.handle_withloc,
            url2)
        contained3 = self.inst.is_URL_contained_in_10320loc(
            self.handle_withloc,
            url3)
        self.assertTrue(contained1,
            'The first added URL was not added.')
        self.assertTrue(contained2,
            'The second added URL was not added.')
        self.assertTrue(contained3,
            'The third added URL was not added.')

    def test_add_additional_URL_to_inexistent_handle(self):
        """Test exception if handle does not exist."""
        with self.assertRaises(HandleNotFoundException):
            self.inst.add_additional_URL(self.inexistent_handle, 'http://foo.foo')

    def test_add_additional_URL_alreadythere(self):
        """Test adding an URL that is already there."""
        url = 'http://first.foo'

        # Precondition: URL is already contained:
        contained = self.inst.is_URL_contained_in_10320loc(
            self.handle_withloc,
            url)
        self.assertTrue(contained,
            'Test precondition failed: URL not there!')

        # Add and check if something has changed:
        record_before = self.inst.retrieve_handle_record(self.handle_withloc)
        self.inst.add_additional_URL(self.handle_withloc, url)
        record_after  = self.inst.retrieve_handle_record(self.handle_withloc)
        record_before = str(record_before).replace(' ','').replace('\'','"')
        record_after = str(record_after).replace(' ','').replace('\'','"')
        self.assertEqual(record_before, record_after,
                        'After adding the same URL again, '
                        'the record was not equal.\n'
                        'Before:\n'+record_before+'\n'
                        'After:\n'+record_after)

    # Remove:

    def test_remove_additional_URL(self):
        """Test normal removal of additional URL from 10320/loc."""
        url = 'http://first.foo'
        self.inst.remove_additional_URL(self.handle_withloc, url)
        contained = self.inst.is_URL_contained_in_10320loc(
            self.handle_withloc,
            url)
        self.assertFalse(contained,
            'After removal, the URL was still there.')

    def test_remove_additional_URL_toempty(self):
        """Test removing all URL, which should remove the whole 10320/loc attribute."""
        url1 =  'http://first.foo'
        url2 = 'http://second.foo'
        self.inst.remove_additional_URL(self.handle_withloc, url1)
        self.inst.remove_additional_URL(self.handle_withloc, url2)

        # Check if empty:
        isempty = self.inst.is_10320loc_empty(self.handle_withloc)
        self.assertTrue(isempty,
            'After removing all URLs from 10320/loc, it is not empty.')

        # Check if still exists:
        rec = self.inst.retrieve_handle_record_json(self.handle_withloc)
        val = self.inst.get_value_from_handle(self.handle_withloc, '10320/loc', rec)
        indices = self.inst.get_handlerecord_indices_for_key('10320/loc', rec['values'])
        self.assertIsNone(val,
            'After removing all URLs from 10320/loc, the value is not None.')
        self.assertEqual(len(indices), 0,
            'After removing all URLs from 10320/loc, the entry still exists.')

