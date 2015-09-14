import unittest
from b2handle.clientcredentials import PIDClientCredentials
from b2handle.handleexceptions import HandleSyntaxError
from b2handle.handleexceptions import CredentialsFormatError
import json

PATH_RES = 'tests/resources'
PATH_CRED = 'tests/testcredentials'
TESTVALUES = json.load(
    open(PATH_RES+'/testvalues_for_clientcredentials_tests_PUBLIC.json'))


class PIDClientCredentials_test(unittest.TestCase):
    """Test case for the PIDClientCredentials class.
    No access to any Handle Server needed."""

    def test_credentials_constructor(self):
        """Test credentials instantiation. No exceptions occur if password or
        serverurl are wrong, or if the username is inexistent. """
        inst = PIDClientCredentials(TESTVALUES['url'],
                                    TESTVALUES['user'],
                                    'some_random_pasword_aksdfadjhfbsdf')
        inst = PIDClientCredentials(TESTVALUES['url'],
                                    '100:not/exist',
                                    'some_random_pasword_aksdfadjhfbsdf')
        inst = PIDClientCredentials('blablabla',
                                    TESTVALUES['user'],
                                    'some_random_pasword_aksdfadjhfbsdf')

    def test_credentials_invalid_username(self):
        """Test error when user name is not index:prefix/suffix."""
        self.assertRaises(HandleSyntaxError, PIDClientCredentials,
                          TESTVALUES['url'],
                          TESTVALUES['handle'],
                          'some_random_pasword_aksdfadjhfbsdf')

    def test_credentials_from_json(self):
        """Test credentials instantiation from JSON file."""
        path_to_json_credentials = PATH_CRED+'/credentials_correct_PUBLIC.json'
        inst = PIDClientCredentials.load_from_JSON(path_to_json_credentials)

    def test_credentials_from_json_username_without_index(self):
        """Test error when user name in json file does not have an index."""
        path_to_json_credentials = PATH_CRED+'/credentials_noindex_PUBLIC.json'
        self.assertRaises(HandleSyntaxError,
                          PIDClientCredentials.load_from_JSON,
                          path_to_json_credentials)

    def test_credentials_from_json_invalid_username(self):
        """Test error when user name in json file is not index:prefix/suffix."""
        path_to_json_credentials = PATH_CRED+'/credentials_wrongusername_PUBLIC.json'
        self.assertRaises(HandleSyntaxError,
                          PIDClientCredentials.load_from_JSON,
                          path_to_json_credentials)

    def test_credentials_from_json_missing_items(self):
        """Test error when items are missing from json credentials file."""
        path_to_json_credentials = PATH_CRED+'/credentials_usernamemissing_PUBLIC.json'
        self.assertRaises(CredentialsFormatError,
                          PIDClientCredentials.load_from_JSON,
                          path_to_json_credentials)


    def test_credentials_from_json_empty_items(self):
        """Test error when items are empty in json credentials file."""
        path_to_json_credentials = PATH_CRED+'/credentials_usernameempty_PUBLIC.json'
        self.assertRaises(CredentialsFormatError,
                          PIDClientCredentials.load_from_JSON,
                          path_to_json_credentials)


