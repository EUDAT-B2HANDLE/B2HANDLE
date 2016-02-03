"""Testing methods that need no server access."""

import sys
if sys.version_info < (2, 7):
    import unittest2 as unittest
else:
    import unittest
import json
sys.path.append("../..")
import b2handle.handlesystemconnector as connector
from b2handle.handleexceptions import HandleSyntaxError
from b2handle.util import check_handle_syntax, check_handle_syntax_with_index, remove_index_from_handle

class EUDATHandleConnectorNoaccessTestCase(unittest.TestCase):


    def setUp(self):
        self.inst = connector.HandleSystemConnector()

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
