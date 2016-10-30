# -*- coding: utf-8 -*-
"""Test cases for the storj.http module."""

from .. import AbstractTestCase
import mock

from hashlib import sha256

from storj import http
from storj import model


class ClientTestCase(AbstractTestCase):
    """Test case for the Client class."""

    def setUp(self):
        super(AbstractTestCase, self).setUp()

        self.email = 'email@example.com'
        self.password = 's3CR3cy'
        self.client = http.Client(self.email, self.password)
        self.client._request = mock.MagicMock()
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
        test_json = {'name': 'Test Bucket', 'storage': 25, 'transfer': 39}
        self.client._request.return_value = test_json

        bucket = self.client.bucket_create('Test Bucket', storage=25,
                                           transfer=39)

        self.client._request.assert_called_once_with(
            method='POST',
            path='/buckets',
            json=test_json)
        self.assertIsInstance(bucket, model.Bucket)

    def test_bucket_delete(self):
        """Test Client.bucket_delete()."""
        bucket_id = '57fd385426adcf743b3d39c5'
        self.client.bucket_delete(bucket_id)

        self.client._request.assert_called_once_with(
            method='DELETE',
            path='/buckets/%s' % bucket_id)

    def test_bucket_files(self):
        """Test Client.bucket_files()."""
        test_bucket_id = "57fd385426adcf743b3d39c5"

        response = self.client.bucket_files(test_bucket_id)

        self.client._request.assert_called_once_with(
            method='GET',
            path='/buckets/%s/files/' % (test_bucket_id))

        self.assertIsNotNone(response)

    def test_bucket_get(self):
        """Test Client.bucket_get()."""
        test_bucket_id = "57fd385426adcf743b3d39c5"
        test_json = {'name': 'Test Bucket', 'storage': 25, 'transfer': 39}

        self.client._request.return_value = test_json

        bucket = self.client.bucket_get(test_bucket_id)

        self.client._request.assert_called_once_with(
            method='GET',
            path='/buckets/%s' % test_bucket_id)
        self.assertIsInstance(bucket, model.Bucket)

    def test_bucket_list(self):
        """Test Client.bucket_list()."""

        # see https://storj.github.io/bridge/#!/buckets/get_buckets
        test_response = [
            {'name': 'Test Bucket 1', 'storage': 25, 'transfer': 39},
            {'name': 'Test Bucket 2', 'storage': 19, 'transfer': 83},
            {'name': 'Test Bucket 3', 'storage': 86, 'transfer': 193}]

        self.client._request.return_value = test_response

        buckets = self.client.bucket_list()

        for bucket in buckets:
            self.assertIsInstance(bucket, model.Bucket)

        self.client._request.assert_called_once_with(
            method='GET',
            path='/buckets')

    def test_bucket_set_keys(self):
        """Test Client.bucket_set_keys()."""

        # see https://storj.github.io/bridge/#!/buckets/patch_buckets_id
        test_bucket_id = '57fd385426adcf743b3d39c5'
        test_bucket_name = 'test'
        test_keys = ['key1', 'key2', 'key3']

        self.client.bucket_set_keys(
            test_bucket_id, test_bucket_name, test_keys)

        response = self.client._request.assert_called_once_with(
            method='PATCH',
            path='/buckets/%s' % test_bucket_id,
            json={
                'name': test_bucket_name,
                'pubkeys': test_keys
            })

        assert response is None

    def test_contacts_list(self):
        """Test Client.contact_list()."""
        test_response = [{'protocol': '0.9.0', 'userAgent': '4.0.2'},
                         {'protocol': '0.8.0', 'userAgent': '4.0.3'}]

        self.client._request.return_value = test_response

        contacts = self.client.contacts_list()

        self.client._request.assert_called_once_with(
            method='GET',
            path='/contacts',
            json={})
        self.assertEqual(contacts, test_response)

    def test_file_pointers(self):
        """Test Client.file_pointers()."""
        test_bucket_id = '1234'
        test_file_id = '5678'

        self.client.token_create = mock.MagicMock()
        self.client.token_create.return_value = {'token': 'test_token'}

        response = self.client.file_pointers(test_bucket_id, test_file_id)

        self.client._request.assert_called_once_with(
            method='GET',
            path='/buckets/%s/files/%s/' % (test_bucket_id, test_file_id),
            headers={'x-token': 'test_token'})

        self.assertIsNotNone(response)

    def test_file_download(self):
        """Test Client.file_download()."""
        pass

    def test_file_upload(self):
        """Test Client.file_upload()."""
        # file_upload is still TODO
        pass

    def test_file_remove(self):
        """Test Client.file_remove()."""
        test_bucket_id = 'lkh39d'
        test_file_id = '72393'

        self.client.file_remove(test_bucket_id, test_file_id)

        self.client._request.assert_called_once_with(
            method='DELETE',
            path='/buckets/%s/files/%s' % (test_bucket_id, test_file_id)
        )

    def test_frame_add_shard(self):
        """Test Client.frame_add_shard()."""
        test_tree = mock.MagicMock()
        test_shard = model.Shard(
            hash='5775772',
            index=7,
            challenges=['0118', 999, 88199, 9119, 725, 3],
            tree=test_tree,
            size=3810)
        test_json = {
            'hash': '5775772',
            'index': 7,
            'challenges': ['0118', 999, 88199, 9119, 725, 3],
            'tree': test_tree,
            'size': 3810}

        test_frame_id = '8193'

        self.client.frame_add_shard(test_shard, test_frame_id)

        self.client._request.assert_called_once_with(
            method='PUT',
            path='/frames/%s' % test_frame_id,
            json=test_json)

    def test_frame_create(self):
        """Test Client.frame_create()."""
        response = self.client.frame_create()

        self.client._request.assert_called_once_with(
            method='POST',
            path='/frames',
            json={})

    def test_frame_delete(self):
        """Test Client.frame_delete()."""
        test_frame_id = '314159265358979265'
        test_json = {
            'frame_id': test_frame_id}

        self.client.frame_delete(test_frame_id)

        self.client._request.assert_called_once_with(
            method='DELETE',
            path='/frames/%s' % test_frame_id,
            json=test_json
        )

    @mock.patch('storj.http.model.Frame', autospec=True)
    def test_frame_get(self, mock_frame):
        """Test Client.frame_get()."""
        test_frame_id = '1234'
        test_json = {
            'created': '2016-03-04T17:01:02.629Z',
            'id': '507f1f77bcf86cd799439011',
            'shards': [{
                'hash': 'fde400fe0b6a5488e10d7317274a096aaa57914d',
                'size': 4096,
                'index': 0}]}

        self.client._request.return_value = test_json

        response = self.client.frame_get(test_frame_id)

        mock_frame.assert_called_with(
            created='2016-03-04T17:01:02.629Z',
            id='507f1f77bcf86cd799439011',
            shards=[{
                'hash': 'fde400fe0b6a5488e10d7317274a096aaa57914d',
                'size': 4096,
                'index': 0}])
        self.client._request.assert_called_once_with(
            method='GET',
            path='/frames/%s' % test_frame_id,
            json={'frame_id': test_frame_id})
        self.assertIsNotNone(response)

    def test_frame_list(self):
        """Test Client.frame_list()."""

        # see https://storj.github.io/bridge/#!/frames/get_frames
        self.client._request.return_value = [{
            'created': '2016-03-04T17:01:02.629Z',
            'id': '507f1f77bcf86cd799439011'
        }]

        response = self.client.frame_list()

        self.client._request.assert_called_once_with(
            method='GET',
            path='/frames')

        assert response is not None
        for frame in response:
            assert isinstance(frame, model.Frame)

    def test_key_delete(self):
        """Test Client.key_delete()."""
        test_key = '39ddkakdi'

        self.client.key_delete(test_key)

        self.client._request.assert_called_once_with(
            method='DELETE',
            path='/keys/%s' % test_key
        )

    @mock.patch('sys.stdout', autospec=True)
    def test_key_dump(self, mock_stdout):
        """Test Client.key_dump()."""
        self.client.private_key = '1234'
        self.client.public_key = '5678'
        test_keys = [
            {'id': 7},
            {'id': 8}]

        self.client.key_get = mock.MagicMock()
        self.client.key_get.return_value = test_keys

        self.client.key_dump()

        calls = [
            mock.call("Local Private Key: %s" % self.client.private_key
                      + "\nLocal Public Key: %s" % self.client.public_key),
            mock.call("\n"),
            mock.call(
                "Public keys for this account: "
                + str([key['id'] for key in test_keys])),
            mock.call("\n")]
        mock_stdout.write.assert_has_calls(calls)

    @mock.patch('sys.stdout', autospec=True)
    def test_key_dump_2(self, mock_stdout):
        """Test Client.key_dump() with missing keys."""
        self.client.private_key = None

        self.client.key_get = mock.MagicMock()
        self.client.key_get.return_value = []

        self.client.key_dump()

        self.client.key_get.assert_called_once_with()

        self.client.logger.info(mock_stdout.write.call_args_list)

        calls = [
            mock.call('No keys associated with this account.'),
            mock.call('\n')]

        mock_stdout.write.assert_has_calls(calls)

    @mock.patch('storj.http.os', autospec=True)
    @mock.patch('storj.http.open', create=True)
    @mock.patch('sys.stdout', autospec=True)
    def test_key_export(self, mock_stdout, mock_open, mock_os):
        """Test Client.key_export()."""
        test_cwd = '~/.keys/'

        mock_os.getcwd.return_value = test_cwd

        mock_file = mock.MagicMock()
        mock_open.return_value = mock_file
        mock_file_handle = mock_open.return_value.__enter__.return_value

        self.client.public_key = mock.MagicMock()
        self.client.public_key.to_pem.return_value = '7'
        self.client.private_key = mock.MagicMock()
        self.client.private_key.to_pem.return_value = '8'

        self.client.key_export()

        open_calls = [
            mock.call('public.pem', 'wb'),
            mock.call('private.pem', 'wb')]
        file_write_calls = [
            mock.call('7'),
            mock.call('8')]
        print_calls = [
            mock.call('Writing your public key to file...'),
            mock.call('\n'),
            mock.call('Writing private key to file... Keep this secret!'),
            mock.call('Wrote keyfiles to dir: ' + test_cwd)]

        mock_open.assert_has_calls(open_calls, any_order=True)
        mock_file_handle.write.assert_has_calls(file_write_calls)
        mock_stdout.write.assert_has_calls(print_calls, any_order=True)

    def test_key_generate(self):
        """Test Client.key_generate()."""
        pass

    def test_key_import(self):
        """Test Client.key_import()."""
        pass

    def test_key_list(self):
        """Test Client.key_list()."""

        self.client._request.return_value = [
            # see https://storj.github.io/bridge/#!/keys/get_keys
            {'user': 'dnr@dnr.com', 'key': 'test_key'}
        ]

        response = self.client.key_list()

        self.client._request.assert_called_once_with(
            method='GET',
            path='/keys'
        )

        assert response is not None
        assert response == ['test_key']

    @mock.patch('storj.http.ecdsa_to_hex')
    def test_key_register(self, mock_ecdsa):
        """Test Client.key_register()."""
        test_hex_key = 'hex encoded key'
        test_json = {'key': test_hex_key}

        mock_ecdsa.return_value = test_hex_key

        response = self.client.key_register('key')

        mock_ecdsa.assert_called_once_with('key')
        self.client._request.assert_called_once_with(
            method='POST',
            path='/keys',
            json=test_json)

    def test_token_create(self):
        """Test Client.token_create()."""
        test_bucket_id = '1234'
        test_json = {'operation': 'PULL'}

        self.client.token_create(test_bucket_id, 'PULL')

        self.client._request.assert_called_once_with(
            method='POST',
            path='/buckets/%s/tokens' % test_bucket_id,
            json=test_json)

    @mock.patch('storj.http.sha256')
    def test_user_create(self, mock_sha256):
        """Test Client.user_create()."""
        test_email = 'a@b.com'
        test_password = 'toast'
        test_hashed_password = 'hashed password'

        mock_sha256.return_value.hexdigest.return_value = test_hashed_password

        self.client.authenticate = mock.MagicMock()

        self.client.user_create(test_email, test_password)

        mock_sha256.assert_called_once_with(test_password)
        mock_sha256.return_value.hexdigest.assert_called_once_with()
        self.client._request.assert_called_once_with(
            method='POST',
            path='/users',
            json={'email': test_email, 'password': test_hashed_password})
        self.client.authenticate.assert_called_once_with(
            email=test_email,
            password=test_hashed_password)
