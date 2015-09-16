"""Testing methods that need Handle server write access"""

import unittest
import logging
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

PATH_RES = 'resources'
TESTVALUES = json.load(open(PATH_RES+'/testvalues_for_clientcredentials_tests_PUBLIC.json'))
TESTVALUES = json.load(open(PATH_RES+'/testvalues_for_integration_tests_IGNORE.json'))

class EUDATHandleClientSearchTestCase(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        unittest.TestCase.__init__(self, *args, **kwargs)
        self.url_https = TESTVALUES['url_https']
        self.password = TESTVALUES['password']
        self.user = TESTVALUES['user']
        self.handle = TESTVALUES['handle_to_be_modified']
        self.handle_withloc = TESTVALUES['handle_with_10320loc']
        self.handle_withoutloc = TESTVALUES['handle_without_10320loc']
        self.newhandle = TESTVALUES['handle_to_be_created']
        self.randompassword = 'some_random_password_dghshsrtsrth'
        self.verify = TESTVALUES['HTTP_verify']

    def setUp(self):
        self.inst = EUDATHandleClient.instantiate_with_username_and_password(
            self.url_https,
            self.user,
            self.password,
            reverselookup_username=TESTVALUES['reverselookup_username'],
            reverselookup_password=TESTVALUES['reverselookup_password'],
            HTTP_verify=self.verify)

    def tearDown(self):
        pass

    def test_search_handle_wrong_url_test(self):
        """Test exception when wrong search servlet URL is given."""
        
        # Query existent but wrong url (google.com):
        self.inst = EUDATHandleClient.instantiate_with_username_and_password(
            self.url_https,
            self.user,
            self.password,
            reverselookup_baseuri='http://www.google.com',
            HTTP_verify=self.verify)

        with self.assertRaises(ReverseLookupException):
            self.inst.search_handle(url='*')

        # Query Handle Server url:
        self.inst = EUDATHandleClient.instantiate_with_username_and_password(
            self.url_https,
            self.user,
            self.password,
            reverselookup_url_extension='/api/handles/',
            HTTP_verify=self.verify)
        
        with self.assertRaises(ReverseLookupException):
            self.inst.search_handle(url='*')

    def test_search_handle(self):
        """Test searching for handles with any url (server should return list of handles)."""
        val = self.inst.search_handle(url='*')
        self.assertEqual(type(val),type([]),
            '')
        self.assertTrue(len(val) > 0,
            '')
        self.assertTrue(self.inst.check_handle_syntax(val[0]),
            '')

    def test_search_handle_emptylist(self):
        """Test empty search result."""
        val = self.inst.search_handle(url='noturldoesnotexist')
        self.assertEqual(type(val),type([]),
            '')
        self.assertEqual(len(val),0,
            '')

    def test_search_handle_for_url(self):
        """Test searching for url with wildcards."""
        val = self.inst.search_handle(url='*dkrz*')
        self.assertEqual(type(val),type([]),
            '')
        val = self.inst.search_handle('*dkrz*')
        self.assertEqual(type(val),type([]),
            '')

    def test_search_handle_for_url_and_checksum(self):
        """Test searching for url and checksum with wildcards."""
        val = self.inst.search_handle('*dkrz*', checksum='*123*')
        self.assertEqual(type(val),type([]),
            '')
        val = self.inst.search_handle(url='*dkrz*', checksum='*123*')
        self.assertEqual(type(val),type([]),
            '')

    def test_search_handle_prefixfilter(self):
        """Test filtering for prefixes."""
        prefix = "11111"
        val = self.inst.search_handle(url='*dkrz*', prefix=prefix)
        self.assertEqual(type(val),type([]),
            '')
        for item in val:
            self.assertEqual(item.split('/')[0], prefix)
        prefix = "10876.test"
        val = self.inst.search_handle(url='*dkrz*', prefix=prefix)
        self.assertEqual(type(val),type([]),
            '')
        for item in val:
            self.assertEqual(item.split('/')[0], prefix)
