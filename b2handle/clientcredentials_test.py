import unittest
#import handleclient_cont as b2handle
from b2handle.clientcredentials import PIDClientCredentials
from handleexceptions import * 
import mock
import requests
import urllib
import json
import xml.etree.ElementTree as ET

TESTVALUES = json.load(open('tests/resources/testvalues_for_clientcredentials_tests_PUBLIC.json'))


class PIDClientCredentials_noaccess_test(unittest.TestCase):

    def init_test(self):
        randompassword='apsodasdjuhfsikjdfskdfj'
        # No exception if password wrong or if server url is wrong, or if user does not exist:
        credentials = PIDClientCredentials(TESTVALUES['url'], TESTVALUES['user'], randompassword)
        credentials = PIDClientCredentials(TESTVALUES['url'], '100:not/exist', randompassword)
        credentials = PIDClientCredentials('blablabla',  TESTVALUES['user'], randompassword)
        # Exception if user is not index:prefix/suffix
        self.assertRaises(HandleSyntaxError, PIDClientCredentials, TESTVALUES['url'], TESTVALUES['handle'], randompassword)
        # 

    def load_from_JSON_test(self):
        pathToJsonCredentials = 'tests/testcredentials/credentials_correct_PUBLIC.json'
        inst = PIDClientCredentials.load_from_JSON(pathToJsonCredentials)
        # Exception if user name is not well formatted:
        pathToJsonCredentials = 'tests/testcredentials/credentials_noindex_PUBLIC.json'
        self.assertRaises(HandleSyntaxError, PIDClientCredentials.load_from_JSON,pathToJsonCredentials)
        pathToJsonCredentials = 'tests/testcredentials/credentials_wrongusername_PUBLIC.json'
        self.assertRaises(HandleSyntaxError, PIDClientCredentials.load_from_JSON,pathToJsonCredentials)
        # Exception if items are missing:
        pathToJsonCredentials = 'tests/testcredentials/credentials_usernamemissing_PUBLIC.json'
        self.assertRaises(CredentialsFormatError, PIDClientCredentials.load_from_JSON,pathToJsonCredentials)
        # Exception if items are empty:
        pathToJsonCredentials = 'tests/testcredentials/credentials_usernameempty_PUBLIC.json'
        self.assertRaises(CredentialsFormatError, PIDClientCredentials.load_from_JSON, pathToJsonCredentials)


