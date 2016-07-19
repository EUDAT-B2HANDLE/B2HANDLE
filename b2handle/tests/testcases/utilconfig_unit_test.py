
import sys
if sys.version_info < (2, 7):
    import unittest2 as unittest
else:
    import unittest

from b2handle.util import get_valid_https_verify


class UtilConfigTestCase(unittest.TestCase):

    def test_valid_https_verify_bool_true(self):
        """Test return bool True when getting bool True"""
        self.assertEqual(get_valid_https_verify(True), True)

    def test_valid_https_verify_string_true(self):
        """Test return bool True when getting string True"""
        self.assertEqual(get_valid_https_verify('True'), True)

    def test_valid_https_verify_string_false(self):
        """Test return bool False when getting string False"""
        self.assertEqual(get_valid_https_verify('False'), False)

    def test_valid_https_verify_unicode_string_true(self):
        """Test return bool True when getting unicode string True"""
        self.assertEqual(get_valid_https_verify(u'True'), True)

    def test_valid_https_verify_unicode_string_false(self):
        """Test return bool False when getting unicode string False"""
        self.assertEqual(get_valid_https_verify(u'False'), False)

    def test_valid_https_verify_bool_string(self):
        """Test return string when getting a string value in https_verify"""
        self.assertEqual(get_valid_https_verify('ca_cert.crt'), 'ca_cert.crt')
