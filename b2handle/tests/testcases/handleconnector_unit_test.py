"""Testing methods that need no server access."""

import sys
if sys.version_info < (2, 7):
    import unittest2 as unittest
else:
    import unittest

import json
import b2handle
from b2handle.handlesystemconnector import HandleSystemConnector
from b2handle.handleexceptions import HandleSyntaxError, CredentialsFormatError
from b2handle.utilhandle import check_handle_syntax, check_handle_syntax_with_index, remove_index_from_handle

# Load some data that is needed for testing
PATH_CRED = b2handle.util.get_neighbour_directory(__file__, 'testcredentials')
FILE_BOTH = PATH_CRED+'/fake_certs_and_keys/fake_certi_and_bothkeys.pem'
FILE_KEY = PATH_CRED+'/fake_certs_and_keys/fake_privatekey.pem'
FILE_CERT = PATH_CRED+'/fake_certs_and_keys/fake_certificate.pem'


class EUDATHandleConnectorNoaccessTestCase(unittest.TestCase):


    def setUp(self):
        self.inst = HandleSystemConnector()

    def tearDown(self):
        pass


    # make_handle_url

    def test_make_handle_url(self):

        url = self.inst.make_handle_URL('testhandle')
        self.assertIn('/api/handles/', url,
            'No REST API path specified in URL: '+url)
        self.assertIn('handle.net', url,
            'handle.net missing in URL: '+url)
        self.assertNotIn('index=', url,
            'Index specified in URL: '+url)
        #self.assertIn('overwrite=false', url,
        #    'overwrite=false is missing: '+url)

    def test_make_handle_url_with_indices(self):

        url = self.inst.make_handle_URL('testhandle', [2,3,5])
        self.assertIn('/api/handles/', url,
            'No REST API path specified in URL: '+url)
        self.assertIn('index=2', url,
            'Index 2 specified in URL: '+url)
        self.assertIn('index=3', url,
            'Index 3 specified in URL: '+url)
        self.assertIn('index=5', url,
            'Index 5 specified in URL: '+url)
        #self.assertIn('overwrite=false', url,
        #    'overwrite=false is missing: '+url)

    def test_make_handle_url_overwrite_true(self):

        url = self.inst.make_handle_URL('testhandle', overwrite=True)
        self.assertIn('/api/handles/', url,
            'No REST API path specified in URL: '+url)
        self.assertIn('overwrite=true', url,
            'overwrite=true is missing: '+url)

    def test_make_handle_url_overwrite_false(self):

        url = self.inst.make_handle_URL('testhandle', overwrite=False)
        self.assertIn('/api/handles/', url,
            'No REST API path specified in URL: '+url)
        self.assertIn('overwrite=false', url,
            'overwrite=false is missing: '+url)

    def test_make_handle_url_otherurl(self):

        other = 'http://foo.foo'
        url = self.inst.make_handle_URL('testhandle', other_url=other)
        self.assertNotIn('/api/handles/', url,
            'REST API path should not be specified in URL: '+url)
        self.assertIn(other, url,
            'Other URL missing in URL: '+url)
        self.assertNotIn('handle.net', url,
            'handle.net should not be in URL: '+url)
        self.assertNotIn('index=', url,
            'Index specified in URL: '+url)
        #self.assertIn('overwrite=false', url,
        #    'overwrite=false is missing: '+url)

    # Initiating:

    def test_init_cert_onefile(self):

        inst = HandleSystemConnector(
            certificate_and_key=FILE_BOTH,
            handle_server_url='http://foo.com'
        )
        self.assertIsInstance(inst, HandleSystemConnector)

    def test_init_cert_twofiles(self):

        inst = HandleSystemConnector(
            certificate_only=FILE_CERT,
            private_key=FILE_KEY,
            handle_server_url='http://foo.com'
        )
        self.assertIsInstance(inst, HandleSystemConnector)

    def test_init_cert_serverurl_missing(self):

        with self.assertRaises(TypeError):
            inst = HandleSystemConnector(FILE_BOTH)
        
    def test_init_privatekey_missing(self):

        inst = HandleSystemConnector(
            certificate_only=FILE_BOTH,
            handle_server_url='http://foo.com'
        )
        self.assertIsInstance(inst, HandleSystemConnector)

    def test_init_certificate_missing(self):

        inst = HandleSystemConnector(
            handle_server_url='http://foo.com',
            private_key=FILE_KEY
        )
        self.assertIsInstance(inst, HandleSystemConnector)

    def test_init_cert_onefile_wrongpath(self):

        with self.assertRaises(CredentialsFormatError):
            inst = HandleSystemConnector(
                certificate_and_key=PATH_CRED+'/noexist.pem',
                handle_server_url='http://foo.com'
            )