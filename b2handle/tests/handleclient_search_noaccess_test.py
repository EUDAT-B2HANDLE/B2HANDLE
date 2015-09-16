"""Testing methods that need Handle server write access"""

import unittest
import json
import sys
sys.path.append("../..")
from b2handle.handleclient import EUDATHandleClient
from b2handle.handleexceptions import ReverseLookupException

PATH_RES = 'resources'


class EUDATHandleClientSearchNoAccessTestCase(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        unittest.TestCase.__init__(self, *args, **kwargs)
        self.testvalues = json.load(open(PATH_RES+'/testvalues_for_integration_tests_IGNORE.json'))
        #self.url_https = self.testvalues['url_https']
        #self.password = self.testvalues['password']
        #self.user = self.testvalues['user']
        #self.handle = self.testvalues['handle_to_be_modified']
        #self.handle_withloc = self.testvalues['handle_with_10320loc']
        #self.handle_withoutloc = self.testvalues['handle_without_10320loc']
        #self.newhandle = self.testvalues['handle_to_be_created']
        #self.randompassword = 'some_random_password_dghshsrtsrth'
        #self.verify = self.testvalues['HTTP_verify']

    def setUp(self):
        self.inst = EUDATHandleClient()
        #self.inst = EUDATHandleClient.instantiate_with_username_and_password(
            #self.url_https,
            #self.user,
            #self.password,
            #reverselookup_username=self.testvalues['reverselookup_username'],
            #reverselookup_password=self.testvalues['reverselookup_password'],
            #HTTP_verify=self.verify
            #)

    def tearDown(self):
        pass

    def test_search_handle_for_forbiddenkeys(self):
        with self.assertRaisesRegexp(ReverseLookupException, 'Cannot search for key[.]*'):
            self.inst.search_handle(url='*dkrz*',
                                          checksum='*123*',
                                          anotherfield='xyz')
        
    def test_search_handle_for_fulltext(self):
        with self.assertRaisesRegexp(ReverseLookupException, 'Full-text search is not implemented yet[.]*'):
            self.inst.search_handle(url='*dkrz*',
                                          checksum='*123*',
                                          searchterms=['searchterm1', 'searchterm2'])

    def test_search_handle_noterms(self):
        with self.assertRaisesRegexp(ReverseLookupException, 'No search terms have been specified[.]*'):
            self.inst.search_handle()

    def test_create_revlookup_query_fulltext(self):
        with self.assertRaisesRegexp(ReverseLookupException, 'Full-text search is not implemented yet[.]*'):
            self.inst.create_revlookup_query('foo', 'bar')

    def test_create_revlookup_query_forbiddenkeys(self):
        with self.assertRaisesRegexp(ReverseLookupException, 'Cannot search for key[.]*'):
            self.inst.create_revlookup_query(foo='foo', bar='bar')

    def test_create_revlookup_query_noterms(self):
        with self.assertRaisesRegexp(ReverseLookupException, 'No search terms have been specified[.]*'):
            self.inst.create_revlookup_query()

    def test_create_revlookup_query_norestriction(self):
        inst = EUDATHandleClient(allowed_search_keys=[])
        query = inst.create_revlookup_query(baz='baz')
        self.assertEqual(query, '?baz=baz',
            'The query is: '+query)

    def test_create_revlookup_query_normal(self):
        query = self.inst.create_revlookup_query(url='foo')
        self.assertEqual(query, '?url=foo',
            'The query is: '+query)