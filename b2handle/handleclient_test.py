'''
Testing methods that need no server access.
'''

import unittest
import b2handle.handleclient as b2handle
from b2handle.handleexceptions import HandleSyntaxError

class EUDATHandleClient_test(unittest.TestCase):

    def setUp(self):
        self.inst = b2handle.EUDATHandleClient()

    def generate_PID_name_test(self):
        uuid = self.inst.generate_PID_name()
        assert '/' not in uuid
        uuid = self.inst.generate_PID_name('aprefix')
        assert 'aprefix/' in uuid

    def init_test(self):
        b2handle.EUDATHandleClient()
        b2handle.EUDATHandleClient('foo')
        b2handle.EUDATHandleClient('http://foo.bar')

    def check_handle_syntax_test(self):
        syntax_checked = self.inst.check_handle_syntax("foo/bar")
        assert syntax_checked == True
        # Exceptions if too many slashes, too few slashes, no prefix, no suffix:
        self.assertRaises(HandleSyntaxError, self.inst.check_handle_syntax, "foo/bar/foo")
        self.assertRaises(HandleSyntaxError, self.inst.check_handle_syntax, "foobar")
        self.assertRaises(HandleSyntaxError, self.inst.check_handle_syntax, "/bar")
        self.assertRaises(HandleSyntaxError, self.inst.check_handle_syntax, "foo/")

    def check_handle_syntax_with_index_test(self):
        syntax_checked = self.inst.check_handle_syntax("300:foo/bar")
        assert syntax_checked == True
        # Exceptions if no index, index wrong, no handle, several indices:
        self.assertRaises(HandleSyntaxError, self.inst.check_handle_syntax_with_index, "nonumber:foo/bar")
        self.assertRaises(HandleSyntaxError, self.inst.check_handle_syntax_with_index, "index/missing")
        self.assertRaises(HandleSyntaxError, self.inst.check_handle_syntax_with_index, "too:many:colons")
        self.assertRaises(HandleSyntaxError, self.inst.check_handle_syntax_with_index, "onlyindex:")

