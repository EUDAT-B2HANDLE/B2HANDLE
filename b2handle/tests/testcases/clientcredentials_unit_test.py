"""Tests for the PIDClientCredentials class. No access to any server/servlet/service needed."""

import sys
import json

if sys.version_info < (2, 7):
    import unittest2 as unittest
else:
    import unittest

import json
import b2handle
from b2handle.clientcredentials import PIDClientCredentials
from b2handle.handleexceptions import HandleSyntaxError, CredentialsFormatError


# Load some data that is needed for testing
PATH_RES = b2handle.util.get_neighbour_directory(__file__, 'resources')
RESOURCES = json.load(open(PATH_RES+'/testvalues_for_clientcredentials_tests_PUBLIC.json'))
PATH_CRED = b2handle.util.get_neighbour_directory(__file__, 'testcredentials')

class PIDClientCredentialsTestCase(unittest.TestCase):
    """Test case for the PIDClientCredentials class.
    No access to any Handle Server needed."""

    def __init__(self, *args, **kwargs):
        unittest.TestCase.__init__(self, *args, **kwargs)
        self.testvalues = RESOURCES
        self.url = self.testvalues['url']
        self.user = self.testvalues['user']
        self.handle = self.testvalues['handle']
        self.prefix = self.testvalues['prefix']
        self.owner = self.testvalues['handleowner']
        self.randompassword = 'some_random_password_lisjfg8473i84urtf'

    # Test constructor:

    def test_credentials_constructor1(self):
        """Test credentials instantiation. No exception occurs if password wrong. """
        inst = PIDClientCredentials(handle_server_url = self.url,
                                    username = self.user,
                                    password = self.randompassword)
        self.assertIsInstance(inst, PIDClientCredentials)

    def test_credentials_constructor2(self):
        """Test credentials instantiation. No exception occurs if username does not exist. """
        inst = PIDClientCredentials(handle_server_url = self.url,
                                    username = '100:not/exist',
                                    password = self.randompassword)
        self.assertIsInstance(inst, PIDClientCredentials)

    def test_credentials_constructor3(self):
        """Test credentials instantiation. No exception occurs if server url does not exist. """
        inst = PIDClientCredentials(handle_server_url = 'blablabla',
                                    username = self.user,
                                    password = self.randompassword)
        self.assertIsInstance(inst, PIDClientCredentials)

    def test_credentials_constructor4(self):
        """Test credentials instantiation. Prefix and handleowner can be passed. """
        inst = PIDClientCredentials(handle_server_url = self.url,
                                    username = self.user,
                                    password = self.randompassword,
                                    prefix = self.prefix,
                                    handleowner = self.owner)
        self.assertIsInstance(inst, PIDClientCredentials)


    def test_credentials_invalid_username(self):
        """Exception occurs when user name is not index:prefix/suffix."""
        with self.assertRaises(HandleSyntaxError):
            inst = PIDClientCredentials(handle_server_url = self.url,
                                        username = self.handle,
                                        password = self.randompassword)

    def test_credentials_invalid_handleowner(self):
        """Exception occurs when handle owner is not index:prefix/suffix."""
        with self.assertRaises(HandleSyntaxError):
            inst = PIDClientCredentials(handle_server_url = self.url,
                                        username = self.handle,
                                        password = self.randompassword,
                                        prefix = self.prefix,
                                        handleowner = '300myhandleowner')
    


    # Read from JSON:

    def test_credentials_from_json(self):
        """Test credentials instantiation from JSON file."""
        path_to_json_credentials = PATH_CRED+'/credentials_correct_PUBLIC.json'
        inst = PIDClientCredentials.load_from_JSON(path_to_json_credentials)
        self.assertIsInstance(inst, PIDClientCredentials)
        
    def test_credentials_from_json_broken_syntax(self):
        """"""
        path_to_json_credentials = PATH_CRED+'/credentials_brokensyntax_PUBLIC.json'
        with self.assertRaises(CredentialsFormatError):
            _inst = PIDClientCredentials.load_from_JSON(path_to_json_credentials)

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

    def test_credentials_from_json_clientcert_onefile(self):
        """Test credentials instantiation from JSON file."""
        path_to_json_credentials = PATH_CRED+'/credentials_correct_with_cert_and_key_PUBLIC.json'
        inst = PIDClientCredentials.load_from_JSON(path_to_json_credentials)
        self.assertIsInstance(inst, PIDClientCredentials)
 
    def test_credentials_from_json_clientcert_twofiles(self):
        """Test credentials instantiation from JSON file."""
        path_to_json_credentials = PATH_CRED+'/credentials_correct_with_cert_PUBLIC.json'
        inst = PIDClientCredentials.load_from_JSON(path_to_json_credentials)
        self.assertIsInstance(inst, PIDClientCredentials)
 
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
        inst = PIDClientCredentials(handle_server_url=self.url,
                                    username=self.user,
                                    password=self.randompassword,
                                    foo='bar',
                                    bar='baz')

        self.assertEqual(inst.get_config()['foo'], 'bar',
            'Config not the same as in json file.')

        self.assertEqual(inst.get_config()['bar'], 'baz',
            'Config not the same as in json file.')


    # Test the getters

    def test_getters(self):
        """Test credentials instantiation from JSON file."""
        path_to_json_credentials = PATH_CRED+'/credentials_correct_PUBLIC.json'
        inst = PIDClientCredentials.load_from_JSON(path_to_json_credentials)
        jsonfilecontent = json.loads(open(path_to_json_credentials, 'r').read())

        self.assertEqual(inst.get_username(), jsonfilecontent['username'],
            'Username not the same as in json file.')
        self.assertEqual(inst.get_password(), jsonfilecontent['password'],
            'Password not the same as in json file.')
        self.assertEqual(inst.get_server_URL(), jsonfilecontent['handle_server_url'],
            'Server URL not the same as in json file.')
        self.assertEqual(inst.get_prefix(), jsonfilecontent['prefix'],
            'Server URL not the same as in json file.')
        self.assertEqual(inst.get_handleowner(), jsonfilecontent['handleowner'],
            'Server URL not the same as in json file.')
