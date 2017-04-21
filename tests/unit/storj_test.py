# -*- coding: utf-8 -*-
"""Test cases for the storj package."""

import mock
import storj


from hashlib import sha256

import storj.configuration
from ecdsa import keys

from .. import AbstractTestCase


class FunctionsTestCase(AbstractTestCase):
    """Test case for the package functions."""

    @mock.patch('storj.read_config')
    def test_get_client(self, mock_read_config):
        mock_read_config.return_value = ('someone@example.com', 'secret')

        client = storj.get_client()

        assert client is not None
        assert client.email == 'someone@example.com'
        assert client.password == sha256('secret'.encode('ascii')).hexdigest()

        mock_read_config.assert_called_once_with()
