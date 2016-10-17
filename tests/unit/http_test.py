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

        self.client._request.assert_called_with(
            method='POST',
            path='/buckets',
            json=test_json)
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

        response = self.client.bucket_files(test_bucket_id)

        self.client._request.assert_called_with(
            method='GET',
            path='/buckets/%s/files/' % (test_bucket_id))

        self.assertIsNotNone(response)

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
            json={'pubkeys': test_keys})

    def test_contacts_list(self):
        """Test Client.contact_list()."""
        test_response = [{'protocol': '0.9.0', 'userAgent': '4.0.2'},
                         {'protocol': '0.8.0', 'userAgent': '4.0.3'}]

        self.client._request.return_value = test_response

        contacts = self.client.contacts_list()

        self.client._request.assert_called_with(
            method='GET',
            path='/contacts',
            json={})
        self.assertEqual(contacts, test_response)

#    @mock.patch('storj.web_socket.Client', autospec=True)
#    @mock.patch('storj.http.BytesIO', autospec=True)
#    def test_file_download(self, mock_BytesIO, mock_web_socket_client):
    def test_file_download(self):
        """Test Client.file_download()."""
#        test_bucket_id = "57fd385426adcf743b3d39c5"
#        test_file_id = "57ffbfd28ce9b61c2634ea5d"
#        test_response = [{
#            'token': '2e5c4f187c1be227c3e1de1f01d202ab06f9f1c7',
#            'operation': 'PULL'}]

#        self.client.bucket_files = mock.MagicMock()
#        self.client.bucket_files.return_value = test_response

#        test_object = mock.MagicMock()
#        mock_BytesIO.return_value = test_object

#        test_file = self.client.file_download(test_bucket_id, test_file_id)

#        mock_web_socket_client.assert_called_with(
#            pointer=test_response[0],
#            file_contents=test_object)
        pass

    def test_file_upload(self):
        """Test Client.file_upload()."""
        pass

    def test_file_remove(self):
        """Test Client.file_remove()."""
        test_bucket_id = 'lkh39d'
        test_file_id = '72393'

        self.client.file_remove(test_bucket_id, test_file_id)

        self.client._request.assert_called_with(
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

        self.client._request.assert_called_with(
            method='PUT',
            path='/frames/%s' % test_frame_id,
            json=test_json)

    def test_frame_create(self):
        """Test Client.frame_create()."""
        response = self.client.frame_create()

        self.client._request.assert_called_with(
            method='POST',
            path='/frames',
            json={})

    def test_frame_delete(self):
        """Test Client.frame_delete()."""
        test_frame_id = '314159265358979265'
        test_json = {
            'frame_id': test_frame_id}

        self.client.frame_delete(test_frame_id)

        self.client._request.assert_called_with(
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
        self.client._request.assert_called_with(
            method='GET',
            path='/frames/%s' % test_frame_id,
            json={'frame_id': test_frame_id})
        self.assertIsNotNone(response)

    def test_frame_list(self):
        """Test Client.frame_list()."""
        self.client._request.return_value = [{
            "created": "2016-03-04T17:01:02.629Z",
            "id": "507f1f77bcf86cd799439011"}]

        response = self.client.frame_list()

        self.client._request.assert_called_with(
            method='GET',
            path='/frames',
            json={})

    def test_key_delete(self):
        """Test Client.key_delete()."""
        test_key = '39ddkakdi'

        self.client.key_delete(test_key)

        self.client._request.assert_called_with(
            method='DELETE',
            path='/keys/%s' % test_key
        )

    @mock.patch('sys.stdout', autospec=True)
    def test_key_dump(self, mock_stdout):
        """Test Client.key_dump()."""
        self.client.private_key = '1234'
        self.client.public_key = '5678'

        self.client.key_get = mock.MagicMock()
        self.client.key_get.return_value = [
            {'id': 7},
            {'id': 8}]

        self.client.key_dump()

        calls = [
            mock.call.write("Local Private Key: " + self.client.private_key
                            + "\nLocal Public Key:" + self.client.public_key),
            mock.call.write("\n"),
            mock.call.write(
                "Public keys for this account: "
                + str([key['id'] for key in self.client.key_get()])),
            mock.call.write("\n")]
        mock_stdout.assert_has_calls(calls)

    def test_key_dump_2(self):
        """Test Client.key_dump() with missing keys."""
        self.client.private_key = None
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
