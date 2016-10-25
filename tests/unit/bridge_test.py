# -*- coding: utf-8 -*-
"""Test cases for the storj.http module."""

from .. import AbstractTestCase
import mock

from storj import bridge
from storj import model


PRIVKEY = "45c6efba90601d9ff8f6f46550cc4661b940f39761963d82529e555ead8e915b"
PUBKEY = "0200802cc451fa39b0730bb5f37a3670e96e9e8e8ea479381f077ff4730fe2ed0b"
PASSWORD = "s3CR3cy"
PW_DIGEST = "67f1a7a10045d97a03312c9332d2c98195408abfb132be141194d8a75898d6da"


class ClientTestCase(AbstractTestCase):
    """Test case for the Client class."""

    def setUp(self):
        super(AbstractTestCase, self).setUp()

        self.email = 'email@example.com'
        self.password = 's3CR3cy'
        self.privkey = PRIVKEY
        self.client = bridge.Client(email=self.email, password=self.password,
                                    privkey=self.privkey)
        self.client._request = mock.MagicMock()

    def test_init(self):
        """Test Client.__init__()."""
        assert self.email == self.client.email
        assert PW_DIGEST == self.client.password

    def test_user_register(self):
        self.client.user_register()
        self.client._request.assert_called_with(
            data={
                'password': PW_DIGEST,
                'pubkey': PUBKEY,
                'email': 'email@example.com'
            },
            method='POST',
            path='/users'
        )

    def test_bucket_create(self):
        """Test Client.bucket_create()."""
        test_json = {'name': 'Test Bucket', 'storage': 25, 'transfer': 39}
        self.client._request.return_value = test_json

        bucket = self.client.bucket_create('Test Bucket', storage=25,
                                           transfer=39)

        self.client._request.assert_called_with(
            method='POST',
            path='/buckets',
            data=test_json
        )
        self.assertIsInstance(bucket, model.Bucket)

    def test_bucket_delete(self):
        """Test Client.bucket_delete()."""
        bucket_id = '57fd385426adcf743b3d39c5'
        self.client.bucket_delete(bucket_id)

        self.client._request.assert_called_with(
            method='DELETE',
            path='/buckets/%s' % bucket_id)

    def test_bucket_files(self):
        """Test Client.bucket_files()."""
        test_bucket_id = "57fd385426adcf743b3d39c5"
        # test_file_id = "57ffbfd28ce9b61c2634ea5d"

        self.client.token_create = mock.MagicMock()
        self.client.token_create.return_value = {'token': 'test_token'}

        self.client.bucket_files(test_bucket_id)

        self.client.token_create.assert_called_with(
            test_bucket_id,
            operation='PULL')
        self.client._request.assert_called_with(
            method='GET',
            path='/buckets/%s/files/' % (test_bucket_id),
            headers={
                'x-token': 'test_token'
            })

    def test_bucket_get(self):
        """Test Client.bucket_get()."""
        test_bucket_id = "57fd385426adcf743b3d39c5"
        test_json = {'name': 'Test Bucket', 'storage': 25, 'transfer': 39}

        self.client._request.return_value = test_json

        bucket = self.client.bucket_get(test_bucket_id)

        self.client._request.assert_called_with(
            method='GET',
            path='/buckets/%s' % test_bucket_id)
        self.assertIsInstance(bucket, model.Bucket)

    def test_bucket_list(self):
        """Test Client.bucket_list()."""
        test_response = [
            {'name': 'Test Bucket 1', 'storage': 25, 'transfer': 39},
            {'name': 'Test Bucket 2', 'storage': 19, 'transfer': 83},
            {'name': 'Test Bucket 3', 'storage': 86, 'transfer': 193}]

        self.client._request.return_value = test_response

        buckets = self.client.bucket_list()

        # _request() is not getting called. Why?
        for bucket in buckets:
            self.assertIsInstance(bucket, model.Bucket)

        self.client._request.assert_called_once_with(
            method='GET',
            path='/buckets')

    def test_bucket_set_keys(self):
        """Test Client.bucket_set_keys()."""
        test_bucket_id = "57fd385426adcf743b3d39c5"
        test_keys = ['key1', 'key2', 'key3']

        self.client.bucket_set_keys(test_bucket_id, test_keys)

        self.client._request.assert_called_with(
            method='PATCH',
            path='/buckets/%s' % test_bucket_id,
            data={'pubkeys': test_keys})

    def test_contacts_list(self):
        """Test Client.contact_list()."""
        test_response = [{'protocol': '0.9.0', 'userAgent': '4.0.2'},
                         {'protocol': '0.8.0', 'userAgent': '4.0.3'}]

        self.client._request.return_value = test_response

        contacts = self.client.contacts_list()

        self.client._request.assert_called_with(
            method='GET',
            path='/contacts',
            params={}
        )
        self.assertEqual(contacts, test_response)

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
