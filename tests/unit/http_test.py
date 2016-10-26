# -*- coding: utf-8 -*-
"""Test cases for the storj.http module."""

from .. import AbstractTestCase
import mock

import jsonschema
import os
from storj import http
from storj import model
from micropayment_core import keys


PRIVKEY = "45c6efba90601d9ff8f6f46550cc4661b940f39761963d82529e555ead8e915b"
PUBKEY = "0200802cc451fa39b0730bb5f37a3670e96e9e8e8ea479381f077ff4730fe2ed0b"
PASSWORD = "s3CR3cy"
PW_DIGEST = "67f1a7a10045d97a03312c9332d2c98195408abfb132be141194d8a75898d6da"


USER_REGISTER_RESULT = {
    "type": "object",
    "properties": {
        "pubkey": {"type": "string"},
        "activated": {"type": "boolean"},
        "id": {"type": "string"},
        "created": {"type": "string"},
        "email": {"type": "string"}
    },
    "additionalProperties": False,
    "required": ["pubkey", "activated", "id", "created", "email"]
}


CONTACTS_LIST_SCHEMA = {
    "type": "array",
    "itmes": {
        "type": {
            "type": "object",
            "properties": {
                "address": "string",
                "port": "integer",
                "nodeID": "string",
                "lastSeen": "string",
                "userAgent": "string",
                "protocol": "string"
            },
            "additionalProperties": False,
            "required": ["address", "port", "nodeID", "lastSeen", "protocol"]
        }
    }
}


USER_ACTIVATE_RESULT = {
    "type": "object",
    "properties": {
        "activated": {"type": "boolean"},
        "created": {"type": "string"},
        "email": {"type": "string"}
    },
    "additionalProperties": False,
    "required": ["activated", "created", "email"]
}


class ProperClientTestCase(AbstractTestCase):

    def test_usage(self):
        super(AbstractTestCase, self).setUp()

        # FIXME move to integration
        client = http.Client(
            email="{0}@bar.com".format(keys.b2h(os.urandom(32))),
            password="12345",
            privkey=keys.generate_privkey(),
            # url="http://api.staging.storj.io/"
        )

        # test call
        apispec = client.call(method="GET")
        self.assertEqual(apispec["info"]["title"], u"Storj Bridge")

        # contacts list
        result = client.contacts_list()
        jsonschema.validate(result, CONTACTS_LIST_SCHEMA)

        # register user
        result = client.user_register()
        jsonschema.validate(result, USER_REGISTER_RESULT)

        # FIXME test activate user
        # result = client.user_activate("TODO get token")
        # jsonschema.validate(result, USER_ACTIVATE_RESULT)


class ClientTestCase(AbstractTestCase):
    """Test case for the Client class."""

    def setUp(self):
        super(AbstractTestCase, self).setUp()

        self.email = 'email@example.com'
        self.password = 's3CR3cy'
        self.privkey = PRIVKEY
        self.client = http.Client(email=self.email, password=self.password,
                                  privkey=self.privkey)

        # FIXME doesnt interacts with bridge, how is it a valid test?
        self.client.call = mock.MagicMock()

    def test_init(self):
        """Test Client.__init__()."""
        assert self.email == self.client.email
        assert PW_DIGEST == self.client.password

    def test_call(self):
        pass

    def test_user_register(self):
        self.client.user_register()
        self.client.call.assert_called_with(
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
        self.client.call.return_value = test_json

        bucket = self.client.bucket_create('Test Bucket', storage=25,
                                           transfer=39)

        self.client.call.assert_called_with(
            method='POST',
            path='/buckets',
            data=test_json
        )
        self.assertIsInstance(bucket, model.Bucket)

    def test_bucket_delete(self):
        """Test Client.bucket_delete()."""
        bucket_id = '57fd385426adcf743b3d39c5'
        self.client.bucket_delete(bucket_id)

        self.client.call.assert_called_with(
            method='DELETE',
            path='/buckets/%s' % bucket_id)

    def test_bucket_files(self):
        """Test Client.bucket_files()."""
        test_bucket_id = "57fd385426adcf743b3d39c5"
        self.client.token_create = mock.MagicMock()
        self.client.token_create.return_value = {'token': 'test_token'}

        response = self.client.bucket_files(test_bucket_id)

        self.client.token_create.assert_called_with(
            test_bucket_id,
            operation='PULL')
        self.client.call.assert_called_with(
            method='GET',
            path='/buckets/%s/files/' % (test_bucket_id),
            headers={'x-token': 'test_token'})

        self.assertIsNotNone(response)

    def test_bucket_get(self):
        """Test Client.bucket_get()."""
        test_bucket_id = "57fd385426adcf743b3d39c5"
        test_json = {'name': 'Test Bucket', 'storage': 25, 'transfer': 39}

        self.client.call.return_value = test_json

        bucket = self.client.bucket_get(test_bucket_id)

        self.client.call.assert_called_with(
            method='GET',
            path='/buckets/%s' % test_bucket_id)
        self.assertIsInstance(bucket, model.Bucket)

    def test_bucket_list(self):
        """Test Client.bucket_list()."""
        test_response = [
            {'name': 'Test Bucket 1', 'storage': 25, 'transfer': 39},
            {'name': 'Test Bucket 2', 'storage': 19, 'transfer': 83},
            {'name': 'Test Bucket 3', 'storage': 86, 'transfer': 193}]

        self.client.call.return_value = test_response

        buckets = self.client.bucket_list()

        for bucket in buckets:
            self.assertIsInstance(bucket, model.Bucket)

        self.client.call.assert_called_once_with(
            method='GET',
            path='/buckets')

    def test_bucket_set_keys(self):
        """Test Client.bucket_set_keys()."""
        test_bucket_id = "57fd385426adcf743b3d39c5"
        test_keys = ['key1', 'key2', 'key3']

        self.client.bucket_set_keys(test_bucket_id, test_keys)

        self.client.call.assert_called_with(
            method='PATCH',
            path='/buckets/%s' % test_bucket_id,
            data={'pubkeys': test_keys})

    def test_contacts_list(self):
        """Test Client.contact_list()."""
        test_response = [{'protocol': '0.9.0', 'userAgent': '4.0.2'},
                         {'protocol': '0.8.0', 'userAgent': '4.0.3'}]

        self.client.call.return_value = test_response

        contacts = self.client.contacts_list()

        self.client.call.assert_called_with(
            method='GET',
            path='/contacts',
            params={}
        )
        self.assertEqual(contacts, test_response)

    def test_file_pointers(self):
        """Test Client.file_pointers()."""
        test_bucket_id = '1234'
        test_file_id = '5678'

        self.client.token_create = mock.MagicMock()
        self.client.token_create.return_value = {'token': 'test_token'}

        response = self.client.file_pointers(test_bucket_id, test_file_id)

        self.client.call.assert_called_with(
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

        self.client.call.assert_called_with(
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

        self.client.call.assert_called_with(
            method='PUT',
            path='/frames/%s' % test_frame_id,
            data=test_json)

    def test_frame_create(self):
        """Test Client.frame_create()."""
        response = self.client.frame_create()

        self.client.call.assert_called_with(
            method='POST',
            path='/frames',
            data={})

    def test_frame_delete(self):
        """Test Client.frame_delete()."""
        test_frame_id = '314159265358979265'
        test_json = {
            'frame_id': test_frame_id}

        self.client.frame_delete(test_frame_id)

        self.client.call.assert_called_with(
            method='DELETE',
            path='/frames/%s' % test_frame_id,
            data=test_json
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

        self.client.call.return_value = test_json

        response = self.client.frame_get(test_frame_id)

        mock_frame.assert_called_with(
            created='2016-03-04T17:01:02.629Z',
            id='507f1f77bcf86cd799439011',
            shards=[{
                'hash': 'fde400fe0b6a5488e10d7317274a096aaa57914d',
                'size': 4096,
                'index': 0}])
        self.client.call.assert_called_with(
            method='GET',
            path='/frames/%s' % test_frame_id,
            data={'frame_id': test_frame_id})
        self.assertIsNotNone(response)

    def test_frame_list(self):
        """Test Client.frame_list()."""
        self.client.call.return_value = [{
            "created": "2016-03-04T17:01:02.629Z",
            "id": "507f1f77bcf86cd799439011"}]

        response = self.client.frame_list()

        self.client.call.assert_called_with(
            method='GET',
            path='/frames',
            data={})

    def test_keys_delete(self):
        """Test Client.keys_delete()."""
        test_key = '39ddkakdi'

        self.client.keys_delete(test_key)

        self.client.call.assert_called_with(
            method='DELETE',
            path='/keys/%s' % test_key
        )

    def test_keys_list(self):
        """Test Client.keys_list()."""
        test_key_dict = [
            {'id': '7', 'user': 'cats@storj.io'},
            {'id': 'a8939', 'user': 'dnr@dnr.com', 'key': 'test_key'}]

        self.client.call.return_value = test_key_dict

        response = self.client.keys_list()

        self.client.call.assert_called_once_with(
            method='GET',
            path='/keys')
        self.assertIsNotNone(response)

    def test_key_import(self):
        """Test Client.key_import()."""
        pass

    def test_token_create(self):
        """Test Client.token_create()."""
        test_bucket_id = '1234'
        test_json = {'operation': 'PULL'}

        self.client.token_create(test_bucket_id, 'PULL')

        self.client.call.assert_called_once_with(
            method='POST',
            path='/buckets/%s/tokens' % test_bucket_id,
            data=test_json)
