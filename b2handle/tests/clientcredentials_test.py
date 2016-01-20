"""Tests for the PIDClientCredentials class. No access to any server/servlet/service needed."""

import sys
if sys.version_info < (2, 7):
    import unittest2 as unittest
else:
    import unittest
import json
sys.path.append("../..")
from b2handle.clientcredentials import PIDClientCredentials
from b2handle.handleexceptions import HandleSyntaxError
from b2handle.handleexceptions import CredentialsFormatError


PATH_RES = 'resources'
PATH_CRED = 'testcredentials'


class PIDClientCredentialsTestCase(unittest.TestCase):
    """Test case for the PIDClientCredentials class.
    No access to any Handle Server needed."""

    def __init__(self, *args, **kwargs):
        unittest.TestCase.__init__(self, *args, **kwargs)
        self.testvalues = json.load(open(
            PATH_RES+'/testvalues_for_clientcredentials_tests_PUBLIC.json'))
        self.url = self.testvalues['url']
        self.user = self.testvalues['user']
        self.handle = self.testvalues['handle']
        self.randompassword = 'some_random_password_lisjfg8473i84urtf'

    def test_credentials_constructor1(self):
        """Test credentials instantiation. No exception occurs if password wrong. """
        inst = PIDClientCredentials(self.url,
                                    self.user,
                                    self.randompassword)
        self.assertIsInstance(inst, PIDClientCredentials)

    def test_credentials_constructor2(self):
        """Test credentials instantiation. No exception occurs if username does not exist. """
        inst = PIDClientCredentials(self.url,
                                    '100:not/exist',
                                    self.randompassword)
        self.assertIsInstance(inst, PIDClientCredentials)

    def test_credentials_constructor3(self):
        """Test credentials instantiation. No exception occurs if server url does not exist. """
        inst = PIDClientCredentials('blablabla',
                                    self.user,
                                    self.randompassword)
        self.assertIsInstance(inst, PIDClientCredentials)

    def test_credentials_constructor4(self):
        """Test credentials instantiation. No exception occurs if server url does not exist. """
        inst = PIDClientCredentials('blablabla',
                                    self.user,
                                    self.randompassword,
                                    'myprefix',
                                    '300:myhandle/owner')
        self.assertIsInstance(inst, PIDClientCredentials)


    def test_credentials_invalid_username(self):
        """Exception occurs when user name is not index:prefix/suffix."""
        with self.assertRaises(HandleSyntaxError):
            inst = PIDClientCredentials(self.url,
                                        self.handle,
                                        self.randompassword)

    def test_credentials_invalid_handleowner(self):
        """Exception occurs when handle owner is not index:prefix/suffix."""
        with self.assertRaises(HandleSyntaxError):
            inst = PIDClientCredentials(self.url,
                                        self.handle,
                                        self.randompassword,
                                        'myprefix',
                                        '300myhandleowner')

    def test_credentials_from_json(self):
        """Test credentials instantiation from JSON file."""
        path_to_json_credentials = PATH_CRED+'/credentials_correct_PUBLIC.json'
        inst = PIDClientCredentials.load_from_JSON(path_to_json_credentials)
        self.assertIsInstance(inst, PIDClientCredentials)

    def test_credentials_from_json_username_without_index(self):
        """Exception occurs if user name in json file does not have an index."""
        path_to_json_credentials = PATH_CRED+'/credentials_noindex_PUBLIC.json'
        with self.assertRaises(HandleSyntaxError):
            _inst = PIDClientCredentials.load_from_JSON(path_to_json_credentials)

    def test_credentials_from_json_invalid_username(self):
        """Exception occurs if user name in json file is not index:prefix/suffix."""
        path_to_json_credentials = PATH_CRED+'/credentials_wrongusername_PUBLIC.json'
        with self.assertRaises(HandleSyntaxError):
            _inst = PIDClientCredentials.load_from_JSON(path_to_json_credentials)

    def test_credentials_from_json_missing_items(self):
        """Exception occurs if items are missing from json credentials file."""
        path_to_json_credentials = PATH_CRED+'/credentials_usernamemissing_PUBLIC.json'
        with self.assertRaises(CredentialsFormatError):
            _inst = PIDClientCredentials.load_from_JSON(path_to_json_credentials)


    def test_credentials_from_json_empty_items(self):
        """Exception occurs if items are empty in json credentials file."""
        path_to_json_credentials = PATH_CRED+'/credentials_usernameempty_PUBLIC.json'
        with self.assertRaises(CredentialsFormatError):
            _inst = PIDClientCredentials.load_from_JSON(path_to_json_credentials)

    def test_getters(self):
        """Test credentials instantiation from JSON file."""
        path_to_json_credentials = PATH_CRED+'/credentials_correct_PUBLIC.json'
        inst = PIDClientCredentials.load_from_JSON(path_to_json_credentials)
        jsonfilecontent = json.loads(open(path_to_json_credentials, 'r').read())

        self.assertEqual(inst.get_username(), jsonfilecontent['username'],
            'Username not the same as in json file.')
        self.assertEqual(inst.get_password(), jsonfilecontent['password'],
            'Password not the same as in json file.')
        self.assertEqual(inst.get_server_URL(), jsonfilecontent['baseuri'],
            'Server URL not the same as in json file.')

    def test_config_from_json(self):
        """Test credentials instantiation from JSON file, with config."""
        path_to_json_credentials = PATH_CRED+'/credentials_correct_withconfig_PUBLIC.json'
        inst = PIDClientCredentials.load_from_JSON(path_to_json_credentials)
        jsonfilecontent = json.loads(open(path_to_json_credentials, 'r').read())

        self.assertEqual(inst.get_config()['foo'], jsonfilecontent['foo'],
            'Config not the same as in json file.')
        self.assertEqual(inst.get_config()['bar'], jsonfilecontent['bar'],
            'Config not the same as in json file.')

    def test_config_from_init(self):
        """Test credentials instantiation from JSON file, with config."""
        inst = PIDClientCredentials(self.url,
                                    self.user,
                                    self.randompassword,
                                    foo='bar',
                                    bar='baz')

        self.assertEqual(inst.get_config()['foo'], 'bar',
            'Config not the same as in json file.')

        self.assertEqual(inst.get_config()['bar'], 'baz',
            'Config not the same as in json file.')
