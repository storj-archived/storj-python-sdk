# -*- coding: utf-8 -*-
"""Test cases for the storj.api module."""

from .. import AbstractTestCase

from storj import api


class FunctionsTestCase(AbstractTestCase):
    """Test case for the module functions."""

    def test_ecdsa_to_hex(self):
        """Test ecdsa_to_hex()."""

        key = b'\xf8\xd2\xaf\xa1\xdb\xa0\xee\xfd\xf9c\x01\xcf\x0c'

        self.assertEqual('04f8d2afa1dba0eefdf96301cf0c', api.ecdsa_to_hex(key))
