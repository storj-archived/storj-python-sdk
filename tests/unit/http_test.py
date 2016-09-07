# -*- coding: utf-8 -*-
"""Test cases for the storj.http module."""

from .. import AbstractTestCase

from hashlib import sha256


from storj import http


class ClientTestCase(AbstractTestCase):
    """Test case for the client class."""

    def setUp(self):
        super(AbstractTestCase, self).setUp()

        self.email = 'email@example.com'
        self.password = 's3CR3cy'
        self.client = http.Client(self.email, self.password)
        self.password_digest = sha256(self.password).hexdigest()

    def test_init(self):
        """Test Client.__init__()."""
        assert self.email == self.client.email
        assert self.password_digest == self.client.password

    def test_add_basic_auth(self):
        """Test Client._add_basic_auth()."""
        request_kwargs = dict(headers={})
        self.client._add_basic_auth(request_kwargs)

        assert 'Authorization' in request_kwargs['headers']
        assert request_kwargs['headers']['Authorization'].startswith('Basic ')
        assert request_kwargs['headers']['Authorization'].endswith('==')
