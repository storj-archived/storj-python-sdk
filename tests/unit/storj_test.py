# -*- coding: utf-8 -*-
"""Test cases for the storj package."""

import storj


from ecdsa import keys

from .. import AbstractTestCase


class FunctionsTestCase(AbstractTestCase):
    """Test case for the package functions."""

    def test_generate_new_key_pair(self):
        """Test generate_new_key_pair()."""

        key, key_pub = storj.generate_new_key_pair()

        self.assertIsNotNone(key)
        self.assertIsNotNone(key_pub)

        self.assertTrue(isinstance(key, keys.SigningKey))
        self.assertTrue(isinstance(key_pub, keys.VerifyingKey))

        self.assertEqual(key_pub, key.get_verifying_key())
        self.assertEqual(32, len(key.to_string()))
