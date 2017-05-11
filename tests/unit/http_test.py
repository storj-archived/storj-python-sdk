# -*- coding: utf-8 -*-
"""Test cases for the storj.http module."""

import mock
import pytest
import requests


from hashlib import sha256


from storj import exception, http, model


from .. import AbstractTestCase


class ClientTestCase(AbstractTestCase):
    """Test case for the Client class."""

    def setUp(self):
        super(AbstractTestCase, self).setUp()

        self.patcher_request = mock.patch.object(http.Client, '_request')
        self.mock_request = self.patcher_request.start()

        self.email = 'email@example.com'
        self.password = 's3CR3cy'
        self.client = http.Client(self.email, self.password)
        self.password_digest = sha256(
            self.password.encode('ascii')).hexdigest()

    def tearDown(self):
        self.patcher_request.stop()

    def test_init(self):
        """Test Client.__init__()."""
        assert self.email == self.client.email
        assert self.password_digest == self.client.password
        assert self.client.do_hashing
        assert self.client.timeout is None

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
        self.mock_request.return_value = test_json

        bucket = self.client.bucket_create(
            test_json['name'],
            storage=test_json['storage'],
            transfer=test_json['transfer']
        )

        self.mock_request.assert_called_once_with(
            method='POST',
            path='/buckets',
            json=test_json)

        assert bucket is not None
        assert isinstance(bucket, model.Bucket)

    def test_bucket_delete(self):
        """Test Client.bucket_delete()."""
        bucket_id = '57fd385426adcf743b3d39c5'
        self.client.bucket_delete(bucket_id)

        response = self.mock_request.assert_called_once_with(
            method='DELETE',
            path='/buckets/%s' % bucket_id)

        assert response is None

    def test_bucket_files(self):
        """Test Client.bucket_files()."""
        test_bucket_id = "57fd385426adcf743b3d39c5"

        response = self.client.bucket_files(test_bucket_id)

        self.mock_request.assert_called_once_with(
            method='GET',
            path='/buckets/%s/files/' % (test_bucket_id))

        self.assertIsNotNone(response)

    def test_bucket_get(self):
        """Test Client.bucket_get()."""
        test_bucket_id = "57fd385426adcf743b3d39c5"
        test_json = {'name': 'Test Bucket', 'storage': 25, 'transfer': 39}

        self.mock_request.return_value = test_json

        bucket = self.client.bucket_get(test_bucket_id)

        self.mock_request.assert_called_once_with(
            method='GET',
            path='/buckets/%s' % test_bucket_id)
        self.assertIsInstance(bucket, model.Bucket)

    def test_bucket_get_not_found(self):
        """Test Client.bucket_get() when bucket does not exist."""

        mock_error = requests.HTTPError()
        mock_error.response = mock.Mock()
        mock_error.response.status_code = 404

        self.mock_request.side_effect = mock_error

        bucket = self.client.bucket_get('inexistent')

        self.mock_request.assert_called_once_with(
            method='GET',
            path='/buckets/inexistent')

        assert bucket is None

    def test_bucket_get_error(self):
        """Test Client.bucket_get() when a bridge error occursr."""

        mock_error = requests.HTTPError()
        mock_error.response = mock.Mock()
        mock_error.response.status_code = 500

        self.mock_request.side_effect = mock_error

        with pytest.raises(exception.BridgeError):
            self.client.bucket_get('error')

        self.mock_request.assert_called_once_with(
            method='GET',
            path='/buckets/error')

    def test_bucket_list(self):
        """Test Client.bucket_list()."""

        # see https://storj.github.io/bridge/#!/buckets/get_buckets
        test_response = [
            {'name': 'Test Bucket 1', 'storage': 25, 'transfer': 39},
            {'name': 'Test Bucket 2', 'storage': 19, 'transfer': 83},
            {'name': 'Test Bucket 3', 'storage': 86, 'transfer': 193}]

        self.mock_request.return_value = test_response

        buckets = self.client.bucket_list()

        assert buckets is not None
        for bucket in buckets:
            assert isinstance(bucket, model.Bucket)

        self.mock_request.assert_called_once_with(
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

        response = self.mock_request.assert_called_once_with(
            method='PATCH',
            path='/buckets/%s' % test_bucket_id,
            json={
                'name': test_bucket_name,
                'pubkeys': test_keys
            })

        assert response is None

    def test_bucket_set_mirrors(self):
        """Test Client.bucket_set_mirrors()."""

        # see https://storj.github.io/bridge/#!/buckets/post_buckets_id_mirrors
        test_bucket_id = '57fd385426adcf743b3d39c5'
        test_file_id = '507f1f77bcf86cd799439011'

        mock_response = {
            'hash': 'fde400fe0b6a5488e10d7317274a096aaa57914d',
            'mirrors': 3,
            'status': 'pending'
        }

        self.mock_request.return_value = mock_response

        mirror = self.client.bucket_set_mirrors(
            test_bucket_id, test_file_id, 3)

        self.mock_request.assert_called_once_with(
            method='POST',
            path='/buckets/%s/mirrors' % test_bucket_id,
            json={
                'file': test_file_id,
                'redundancy': 3})

        assert mirror is not None
        assert isinstance(mirror, model.Mirror)

    def test_contact_list(self):
        """Test Client.contact_list()."""
        test_response = [
            {'protocol': '0.9.0', 'userAgent': '4.0.2'},
            {'protocol': '0.8.0', 'userAgent': '4.0.3'}
        ]

        self.mock_request.return_value = test_response

        contacts = self.client.contact_list()

        assert contacts is not None
        for contact in contacts:
            assert isinstance(contact, model.Contact)

        self.mock_request.assert_called_once_with(
            method='GET',
            path='/contacts')

    def test_contact_lookup(self):
        """Test Client.contact_lookup()."""
        test_response = {
            'protocol': '0.8.0', 'userAgent': '4.0.3'
        }

        self.mock_request.return_value = test_response

        contact = self.client.contact_lookup('node_id')

        assert contact is not None
        assert isinstance(contact, model.Contact)

        self.mock_request.assert_called_once_with(
            method='GET',
            path='/contacts/%s' % 'node_id')

    @mock.patch.object(http.Client, 'token_create')
    def test_file_pointers(self, mock_token_create):
        """Test Client.file_pointers()."""
        test_bucket_id = '1234'
        test_file_id = '5678'
        test_limit = '10'
        test_skip = '0'
        test_exclude = ['1234567890', '2345678901']

        mock_token_create.return_value = model.Token(id='test_token')

        response = self.client.file_pointers(
            test_bucket_id, test_file_id, test_skip, test_limit, test_exclude)

        assert response is not None
        for pointer in response:
            assert isinstance(pointer, model.FilePointer)

        exclude = ','.join(test_exclude)
        self.mock_request.assert_called_once_with(
            method='GET',
            path='/buckets/%s/files/%s/?skip=%s&limit=%s&exclude=%s' % (
                test_bucket_id, test_file_id, test_skip, test_limit, exclude),
            headers={'x-token': 'test_token'})

        mock_token_create.assert_called_once_with(
            test_bucket_id, operation='PULL')

    def test_file_download(self):
        """Test Client.file_download()."""
        pass

    def test_file_metadata(self):
        """Test Client.file_metadata()."""
        test_bucket_id = 'lkh39d'
        test_file_id = '72393'

        # https://storj.github.io/bridge/#!/buckets/get_buckets_id_files_file_id_info
        self.mock_request.return_value = {
            'bucket': '507f1f77bcf86cd799439011',
            'mimetype': 'video/mpeg',
            'filename': 'big_buck_bunny.mp4',
            'frame': '507f1f77bcf86cd799439191',
            'id': '507f1f77bcf86cd799430909',
            'size': 5071076
        }

        metadata = self.client.file_metadata(test_bucket_id, test_file_id)

        assert metadata is not None
        assert isinstance(metadata, model.File)

        self.mock_request.assert_called_once_with(
            method='GET',
            path='/buckets/%s/files/%s/info' % (test_bucket_id, test_file_id)
        )

    def test_file_upload(self):
        """Test Client.file_upload()."""
        # file_upload is still TODO
        pass

    def test_file_remove(self):
        """Test Client.file_remove()."""
        test_bucket_id = 'lkh39d'
        test_file_id = '72393'

        self.client.file_remove(test_bucket_id, test_file_id)

        self.mock_request.assert_called_once_with(
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
            'exclude': None,
            'hash': '5775772',
            'index': 7,
            'challenges': ['0118', 999, 88199, 9119, 725, 3],
            'tree': test_tree.leaves,
            'size': 3810}

        test_frame_id = '8193'

        self.client.frame_add_shard(test_shard, test_frame_id)

        self.mock_request.assert_called_once_with(
            method='PUT',
            path='/frames/%s' % test_frame_id,
            json=test_json)

    def test_frame_create(self):
        """Test Client.frame_create()."""

        frame = self.client.frame_create()

        self.mock_request.assert_called_once_with(
            method='POST',
            path='/frames')

        assert frame is not None
        assert isinstance(frame, model.Frame)

    def test_frame_delete(self):
        """Test Client.frame_delete()."""
        test_frame_id = '314159265358979265'
        test_json = {
            'frame_id': test_frame_id}

        self.client.frame_delete(test_frame_id)

        self.mock_request.assert_called_once_with(
            method='DELETE',
            path='/frames/%s' % test_frame_id,
            json=test_json
        )

    def test_frame_get(self):
        """Test Client.frame_get()."""
        test_frame_id = '1234'
        test_json = {
            'created': '2016-03-04T17:01:02.629Z',
            'id': '507f1f77bcf86cd799439011',
            'shards': [{
                'hash': 'fde400fe0b6a5488e10d7317274a096aaa57914d',
                'size': 4096,
                'index': 0}]}

        self.mock_request.return_value = test_json

        frame = self.client.frame_get(test_frame_id)

        self.mock_request.assert_called_once_with(
            method='GET',
            path='/frames/%s' % test_frame_id,
            json={'frame_id': test_frame_id})

        assert frame is not None
        assert isinstance(frame, model.Frame)

    def test_frame_list(self):
        """Test Client.frame_list()."""

        # see https://storj.github.io/bridge/#!/frames/get_frames
        self.mock_request.return_value = [{
            'created': '2016-03-04T17:01:02.629Z',
            'id': '507f1f77bcf86cd799439011'
        }]

        response = self.client.frame_list()

        assert response is not None
        for frame in response:
            assert isinstance(frame, model.Frame)

        self.mock_request.assert_called_once_with(
            method='GET',
            path='/frames')

    def test_key_delete(self):
        """Test Client.key_delete()."""
        test_key = '39ddkakdi'

        self.client.key_delete(test_key)

        self.mock_request.assert_called_once_with(
            method='DELETE',
            path='/keys/%s' % test_key
        )

    @mock.patch.object(http.Client, 'key_list')
    @mock.patch('sys.stdout', autospec=True)
    def test_key_dump(self, mock_stdout, mock_key_list):
        """Test Client.key_dump()."""
        self.client.private_key = '1234'
        self.client.public_key = '5678'
        test_keys = [
            {'id': 7},
            {'id': 8}
        ]

        mock_key_list.return_value = test_keys

        self.client.key_dump()

        mock_key_list.assert_called_once_with()

        calls = [
            mock.call("Local Private Key: %s" % self.client.private_key
                      + "\nLocal Public Key: %s" % self.client.public_key),
            mock.call("\n"),
            mock.call(
                "Public keys for this account: "
                + str([key['id'] for key in test_keys])),
            mock.call("\n")]
        mock_stdout.write.assert_has_calls(calls)

    @mock.patch.object(http.Client, 'key_list', return_value=[])
    @mock.patch('sys.stdout', autospec=True)
    def test_key_dump_missing_keys(self, mock_stdout, mock_key_list):
        """Test Client.key_dump() with missing keys."""
        self.client.private_key = None

        self.client.key_dump()

        mock_key_list.assert_called_once_with()
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

        self.mock_request.return_value = [
            # see https://storj.github.io/bridge/#!/keys/get_keys
            {'user': 'dnr@dnr.com', 'key': 'test_key'}
        ]

        response = self.client.key_list()

        self.mock_request.assert_called_once_with(
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

        assert response is None

        mock_ecdsa.assert_called_once_with('key')
        self.mock_request.assert_called_once_with(
            method='POST',
            path='/keys',
            json=test_json)

    def test_token_create(self):
        """Test Client.token_create()."""

        test_bucket_id = '1234'
        test_json = {'operation': 'PULL'}

        # https://storj.github.io/bridge/#!/buckets/post_buckets_id_tokens
        self.mock_request.return_value = dict(
            id='string',
            bucket='string',
            expires='2016-10-13T04:23:48.183Z',
            operation='string',
            encryptionKey='string'
        )

        response = self.client.token_create(test_bucket_id, 'PULL')

        assert response is not None
        assert isinstance(response, model.Token)

        self.mock_request.assert_called_once_with(
            method='POST',
            path='/buckets/%s/tokens' % test_bucket_id,
            json=test_json)

    def test_user_activate(self):
        """Test Client.user_activate()."""

        self.mock_request.return_value = None

        response = self.client.user_activate('token')

        assert response is None

        self.mock_request.assert_called_once_with(
            method='GET',
            path='/activations/token')

    def test_user_activation_email(self):
        """Test Client.user_activation_email()."""

        self.mock_request.return_value = None

        response = self.client.user_activation_email('email', 'token')

        assert response is None

        self.mock_request.assert_called_once_with(
            method='GET',
            path='/activations/token',
            json={'email': 'email'})

    @mock.patch('storj.http.sha256')
    def test_user_create(self, mock_sha256):
        """Test Client.user_create()."""
        test_email = 'a@b.com'
        test_password = 'toast'
        test_hashed_password = 'hashed password'

        mock_sha256.return_value.hexdigest.return_value = test_hashed_password

        self.client.user_create(test_email, test_password)

        mock_sha256.assert_called_once_with(test_password)
        mock_sha256.return_value.hexdigest.assert_called_once_with()

        self.mock_request.assert_called_once_with(
            method='POST',
            path='/users',
            json={'email': test_email, 'password': test_hashed_password})

    def test_user_deactivate(self):
        """Test Client.user_deactivate()."""

        self.mock_request.return_value = None

        response = self.client.user_deactivate('token')

        assert response is None

        self.mock_request.assert_called_once_with(
            method='DELETE',
            path='/activations/token')

    def test_user_delete(self):
        """Test Client.user_delete()."""

        self.mock_request.return_value = None

        response = self.client.user_delete('email')

        assert response is None

        self.mock_request.assert_called_once_with(
            method='DELETE',
            path='/users/email')

    def test_user_reset_password(self):
        """Test Client.user_reset_password()."""

        self.mock_request.return_value = None

        response = self.client.user_reset_password('email')

        assert response is None

        self.mock_request.assert_called_once_with(
            method='PATCH',
            path='/users/email')

    def test_user_reset_password_confirmation(self):
        """Test Client.user_reset_password_confirmation()."""

        self.mock_request.return_value = None

        response = self.client.user_reset_password_confirmation('token')

        assert response is None

        self.mock_request.assert_called_once_with(
            method='GET',
            path='/resets/token')
