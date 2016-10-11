# -*- coding: utf-8 -*-
"""Test cases for the storj.http module."""

from .. import AbstractTestCase

from hashlib import sha256

from storj import http
from storj import model


class ClientTestCase(AbstractTestCase):
    """Test case for the client class."""

    def setUp(self):
        super(AbstractTestCase, self).setUp()

        self.email = 'email@example.com'
        self.password = 's3CR3cy'
        self.client = http.Client(self.email, self.password)
        self.password_digest = sha256(
            self.password.encode('ascii')).hexdigest()

    def test_init(self):
        """Test Client.__init__()."""
        assert self.email == self.client.email
        assert self.password_digest == self.client.password

    def test_add_basic_auth(self):
        """Test Client._add_basic_auth()."""
        request_kwargs = dict(headers={})
        self.client._add_basic_auth(request_kwargs)

        assert 'Authorization' in request_kwargs['headers']
        assert request_kwargs['headers']['Authorization'].startswith(b'Basic ')
        assert request_kwargs['headers']['Authorization'].endswith(b'==')

    def test_bucket_create(self):
        """Test Client.bucket_create()."""
        bucket = self.client.bucket_create("Test Bucket",
                                           storage=25, transfer=39)

        assert isinstance(bucket, model.Bucket)

    def test_bucket_delete(self):
        """Test Client.bucket_delete()."""
        pass

    def test_bucket_files(self):
        """Test Client.bucket_files()."""
        pass

    def test_bucket_get(self):
        """Test Client.bucket_get()."""
        pass

    def test_bucket_list(self):
        """Test Client.bucket_list()."""
        pass

    def test_bucket_set_keys(self):
        """Test Client.bucket_set_keys()."""
        pass

    def test_contact_list(self):
        """Test Client.contact_list()."""
        pass

    def test_file_download(self):
        """Test Client.file_download()."""
        pass

    def test_file_get(self):
        """Test Client.file_get()."""
        pass

    def test_file_upload(self):
        """Test Client.file_upload()."""
        pass

    def test_file_remove(self):
        """Test Client.file_remove()."""
        pass

    def test_frame_add_shard(self):
        """Test Client.frame_add_shard()."""
        pass

    def test_frame_create(self):
        """Test Client.frame_create()."""
        pass

    def test_frame_delete(self):
        """Test Client.frame_delete()."""
        pass

    def test_frame_get(self):
        """Test Client.frame_get()."""
        pass

    def test_frame_list(self):
        """Test Client.frame_list()."""
        pass

    def test_key_delete(self):
        """Test Client.key_delete()."""
        pass

    def test_key_dump(self):
        """Test Client.key_dump()."""
        pass

    def test_key_export(self):
        """Test Client.key_export()."""
        pass

    def test_key_generate(self):
        """Test Client.key_generate()."""
        pass

    def test_key_get(self):
        """Test Client.key_get()."""
        pass

    def test_key_import(self):
        """Test Client.key_import()."""
        pass

    def test_key_register(self):
        """Test Client.key_register()."""
        pass

    def test_token_create(self):
        """Test Client.token_create()."""
        pass

    def test_user_create(self):
        """Test Client.user_create()."""
        pass
