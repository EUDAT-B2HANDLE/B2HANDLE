"""Testing methods that need no server access."""

import sys
if sys.version_info < (2, 7):
    import unittest2 as unittest
else:
    import unittest

import json
import b2handle
from b2handle.handleclient import EUDATHandleClient
from b2handle.handleexceptions import HandleSyntaxError
from b2handle.utilhandle import check_handle_syntax, check_handle_syntax_with_index, remove_index_from_handle, create_authentication_string

class EUDATHandleClientNoaccessTestCase(unittest.TestCase):


    def setUp(self):
        self.inst = EUDATHandleClient()

    def tearDown(self):
        pass

    # Init

    def test_constructor_no_args(self):
        """Test constructor without args: No exception raised."""
        inst = EUDATHandleClient()
        self.assertIsInstance(inst, EUDATHandleClient,
            'Not a client instance!')

    def test_constructor_with_url(self):
        """Test constructor with one arg (well-formatted server URL): No exception raised."""
        inst = EUDATHandleClient('http://foo.bar')
        self.assertIsInstance(inst, EUDATHandleClient,
            'Not a client instance!')

    def test_constructor_with_url(self):
        """Test constructor with one arg (ill-formatted server URL): No exception raised."""
        inst = EUDATHandleClient('foo')
        self.assertIsInstance(inst, EUDATHandleClient,
            'Not a client instance!')

    def test_instantiate_for_read_access(self):
        """Testing if instantiating with default handle server works. """

        # Create client instance with username and password
        inst = EUDATHandleClient.instantiate_for_read_access()
        self.assertIsInstance(inst, EUDATHandleClient)

    def test_instantiate_for_read_an_search(self):
        """Testing if instantiating with default handle server works. """

        # Try to create client instance for search without a search URL:
        with self.assertRaises(TypeError):
            inst = EUDATHandleClient.instantiate_for_read_and_search(
                None, 'johndoe', 'passywordy')

    def test_instantiate_with_username_and_password_noindex(self):

        # Try to ceate client instance with username and password

        with self.assertRaises(HandleSyntaxError):
            inst = EUDATHandleClient.instantiate_with_username_and_password(
                'someurl', 'johndoe', 'passywordy')

    # PID generation

    def test_generate_PID_name_without_prefix(self):
        """Test PID generation without prefix."""
        uuid = self.inst.generate_PID_name()
        self.assertFalse('/' in uuid,
            'There is a slash in the generated PID, even though no prefix was specified.')

    def test_generate_PID_name_with_prefix(self):
        """Test PID generation with prefix."""
        prefix = 'aprefix'
        uuid = self.inst.generate_PID_name(prefix)
        self.assertTrue(prefix+'/' in uuid,
            'The specified prefix is not present in the generated PID.')

    # Handle syntax

    def test_check_handle_syntax_normal(self):
        """Test check handle syntax"""
        syntax_checked = check_handle_syntax("foo/bar")
        self.assertTrue(syntax_checked)

    def test_check_handle_syntax_two_slashes(self):
        """Handle Syntax: No exception if too many slashes in handle."""
        check_handle_syntax("foo/bar/foo")

    def test_check_handle_syntax_no_slashes(self):
        """Handle Syntax: Exception if too many slashes in handle."""
        with self.assertRaises(HandleSyntaxError):
            check_handle_syntax("foobar")

    def test_check_handle_syntax_no_prefix(self):
        """Handle Syntax: Exception if no prefix."""
        with self.assertRaises(HandleSyntaxError):
            check_handle_syntax("/bar")

    def test_check_handle_syntax_no_suffix(self):
        """Handle Syntax: Exception if no suffix."""
        with self.assertRaises(HandleSyntaxError):
            check_handle_syntax("foo/")

    def test_check_handle_syntax_with_index(self):
        """Test check handle syntax with index."""
        syntax_checked = check_handle_syntax("300:foo/bar")
        self.assertTrue(syntax_checked,
            'The syntax of the handle is not index:prefix/suffix.')

    def test_check_handle_syntax_none(self):
        """Test check handle syntax where handle is None"""
        with self.assertRaises(HandleSyntaxError):
            syntax_checked = check_handle_syntax(None)

    def test_check_handle_syntax_with_index_nan(self):
        """Handle Syntax: Exception if index not a number."""
        with self.assertRaises(HandleSyntaxError):
            check_handle_syntax_with_index("nonumber:foo/bar")

    def test_check_handle_syntax_with_index_noindex(self):
        """Handle Syntax: Exception if index not existent."""
        with self.assertRaises(HandleSyntaxError):
            check_handle_syntax_with_index("index/missing")

    def test_check_handle_syntax_with_index_twocolons(self):
        """Handle Syntax: Exception if two colons."""
        with self.assertRaises(HandleSyntaxError):
            check_handle_syntax_with_index("too:many:colons")

    def test_check_handle_syntax_with_index_onlyindex(self):
        """Handle Syntax: Exception if no prefix and suffix."""
        with self.assertRaises(HandleSyntaxError):
            check_handle_syntax_with_index("onlyindex:")

    def test_remove_index_from_handle(self):
        handle_with_index = "300:foo/bar"
        syntax_checked = check_handle_syntax(handle_with_index)
        self.assertTrue(syntax_checked,
            'Test precondition failed!')
        index, handle = remove_index_from_handle(handle_with_index)
        syntax_checked = check_handle_syntax(handle)
        self.assertTrue(syntax_checked,
            'After removing the index, the syntax of the handle should '+\
            'be prefix/suffix.')

    def test_remove_index_noindex(self):
        handle_with_index = "foo/bar"
        syntax_checked = check_handle_syntax(handle_with_index)
        self.assertTrue(syntax_checked,
            'Test precondition failed!')
        index, handle = remove_index_from_handle(handle_with_index)
        syntax_checked = check_handle_syntax(handle)
        self.assertTrue(syntax_checked,
            'After removing the index, the syntax of the handle should '+\
            'be prefix/suffix.')

    def test_remove_index_toomany(self):
        handle_with_index = "100:100:foo/bar"
        with self.assertRaises(HandleSyntaxError):
            index, handle = remove_index_from_handle(handle_with_index)

    # retrieve handle record (failing before any server access)

    def test_retrieve_handle_record_json_handlesyntax_wrong(self):
        """Test exception if handle syntax is wrong (retrieve_handle_record_json)."""

        with self.assertRaises(HandleSyntaxError):
            json_record = self.inst.retrieve_handle_record_json('testhandle')

    def test_retrieve_handle_record_when_handle_is_None(self):
        """Test error when retrieving a handle record with a None input."""

        # Call method and check result:
        with self.assertRaises(HandleSyntaxError):
            self.inst.retrieve_handle_record(None)

    # make_authentication_string

    def test_create_authentication_string(self):
        auth = create_authentication_string('100:user/name', 'password123')
        expected = 'MTAwJTNBdXNlci9uYW1lOnBhc3N3b3JkMTIz'
        self.assertEquals(expected, auth,
            'Authentication string is: '+auth+', but should be: '+expected)

    