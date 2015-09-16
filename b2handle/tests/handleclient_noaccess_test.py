"""Testing methods that need no server access."""

import unittest
import json
import sys
sys.path.append("../..")
import b2handle.handleclient as b2handle
from b2handle.handleexceptions import HandleSyntaxError

class EUDATHandleClientNoaccessTestCase(unittest.TestCase):


    def setUp(self):
        self.inst = b2handle.EUDATHandleClient()

    def tearDown(self):
        pass

    # Init

    def test_constructor_no_args(self):
        """Test constructor without args: No exception raised."""
        b2handle.EUDATHandleClient()

    def test_constructor_with_url(self):
        """Test constructor with one arg (well-formatted server URL): No exception raised."""
        b2handle.EUDATHandleClient('http://foo.bar')

    def test_constructor_with_url(self):
        """Test constructor with one arg (ill-formatted server URL): No exception raised."""
        b2handle.EUDATHandleClient('foo')

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
        syntax_checked = self.inst.check_handle_syntax("foo/bar")
        self.assertTrue(syntax_checked)

    def test_check_handle_syntax_two_slashes(self):
        """Handle Syntax: Exception if too many slashes in handle."""
        with self.assertRaises(HandleSyntaxError):
            self.inst.check_handle_syntax("foo/bar/foo")

    def test_check_handle_syntax_no_slashes(self):
        """Handle Syntax: Exception if too many slashes in handle."""
        with self.assertRaises(HandleSyntaxError):
            self.inst.check_handle_syntax("foobar")

    def test_check_handle_syntax_no_prefix(self):
        """Handle Syntax: Exception if no prefix."""
        with self.assertRaises(HandleSyntaxError):
            self.inst.check_handle_syntax("/bar")

    def test_check_handle_syntax_no_suffix(self):
        """Handle Syntax: Exception if no suffix."""
        with self.assertRaises(HandleSyntaxError):
            self.inst.check_handle_syntax("foo/")

    def test_check_handle_syntax_with_index(self):
        """Test check handle syntax with index."""
        syntax_checked = self.inst.check_handle_syntax("300:foo/bar")
        self.assertTrue(syntax_checked,
            'The syntax of the handle is not index:prefix/suffix.')

    def test_check_handle_syntax_with_index_nan(self):
        """Handle Syntax: Exception if index not a number."""
        with self.assertRaises(HandleSyntaxError):
            self.inst.check_handle_syntax_with_index("nonumber:foo/bar")

    def test_check_handle_syntax_with_index_noindex(self):
        """Handle Syntax: Exception if index not existent."""
        with self.assertRaises(HandleSyntaxError):
            self.inst.check_handle_syntax_with_index("index/missing")

    def test_check_handle_syntax_with_index_twocolons(self):
        """Handle Syntax: Exception if two colons."""
        with self.assertRaises(HandleSyntaxError):
            self.inst.check_handle_syntax_with_index("too:many:colons")

    def test_check_handle_syntax_with_index_onlyindex(self):
        """Handle Syntax: Exception if no prefix and suffix."""
        with self.assertRaises(HandleSyntaxError):
            self.inst.check_handle_syntax_with_index("onlyindex:")

    def test_remove_index(self):
        handle_with_index = "300:foo/bar"
        syntax_checked = self.inst.check_handle_syntax(handle_with_index)
        self.assertTrue(syntax_checked,
            'Test precondition failed!')
        index, handle = self.inst.remove_index(handle_with_index)
        syntax_checked = self.inst.check_handle_syntax(handle)
        self.assertTrue(syntax_checked,
            'After removing the index, the syntax of the handle should '+\
            'be prefix/suffix.')

    def test_retrieve_handle_record_json_handlesyntax_wrong(self):
        """Test exception if handle syntax is wrong (retrieve_handle_record_json)."""

        with self.assertRaises(HandleSyntaxError):
            json_record = self.inst.retrieve_handle_record_json('testhandle')