# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import io
from datetime import datetime

from pytz import utc

from .api import api_client, ecdsa_to_hex, MetadiskApiError


class Bucket:

    def __init__(self, json_payload):
        try:
            self.id = json_payload['id']
            self.name = json_payload['name']
            self.status = json_payload['status']
            self.user = json_payload['user']
            self.created_at = json_payload['created']
            self.storage = json_payload['storage']
            self.transfer = json_payload['transfer']
            self.authorized_public_keys = json_payload['pubkeys']
        except KeyError as e:
            raise MetadiskApiError(
                'Field "{field}" not present in JSON payload'.format(field=e.args[0])
            )

        self.files = FileManager(bucket_id=self.id)
        self.authorized_public_keys = BucketKeyManager(bucket=self, authorized_public_keys=self.authorized_public_keys)
        self.tokens = TokenManager(bucket_id=self.id)
        self.created_at = datetime.strptime(self.created_at, '%Y-%m-%dT%H:%M:%S.%fZ').replace(tzinfo=utc)

    def __str__(self):
        return self.name

    def __repr__(self):
        return 'Bucket {id} ({name})'.format(id=self.id, name=self.name)

    def delete(self):
        BucketManager.delete(bucket_id=self.id)


class BucketManager:

    @staticmethod
    def all():
        buckets_json = api_client.get_buckets()
        return [Bucket(payload) for payload in buckets_json]

    @staticmethod
    def get(bucket_id):
        bucket_json = api_client.get_bucket(bucket_id=bucket_id)
        return Bucket(bucket_json)

    @staticmethod
    def create(name, storage_limit=None, transfer_limit=None):
        bucket_json = api_client.create_bucket(
            bucket_name=name,
            storage_limit=storage_limit,
            transfer_limit=transfer_limit,
        )
        return Bucket(bucket_json)

    @staticmethod
    def delete(bucket_id):
        api_client.delete_bucket(bucket_id=bucket_id)


class BucketKeyManager:

    def __init__(self, bucket, authorized_public_keys):
        self.bucket = bucket
        self._authorized_public_keys = authorized_public_keys

    def all(self):
        return self._authorized_public_keys

    def add(self, key):

        if not isinstance(key, str):
            key = ecdsa_to_hex(key)

        self._authorized_public_keys.append(key)
        api_client.set_bucket_pubkeys(bucket_id=self.bucket.id, keys=self._authorized_public_keys)

    def remove(self, key):

        if not isinstance(key, str):
            key = ecdsa_to_hex(key)

        self._authorized_public_keys.remove(key)
        api_client.set_bucket_pubkeys(bucket_id=self.bucket.id, keys=self._authorized_public_keys)

    def clear(self):
        self._authorized_public_keys = []
        api_client.set_bucket_pubkeys(bucket_id=self.bucket.id, keys=[])


class UserKeyManager:

    @staticmethod
    def all():
        keys_json = api_client.get_keys()
        return [payload['key'] for payload in keys_json]

    @staticmethod
    def add(key):

        if not isinstance(key, str):
            key = ecdsa_to_hex(key)

        api_client.register_ecdsa_key(key)

    @staticmethod
    def remove(key):

        if not isinstance(key, str):
            key = ecdsa_to_hex(key)

        api_client.delete_key(key)

    @staticmethod
    def clear():
        for key in UserKeyManager.all():
            UserKeyManager.remove(key)


class Token:

    def __init__(self, json_payload):
        self.id = json_payload['token']
        self.bucket_id = json_payload['bucket']
        self.operation = json_payload['operation']
        self.expires_at = json_payload['expires']
        self.expires_at = datetime.strptime(self.expires_at, '%Y-%m-%dT%H:%M:%S.%fZ').replace(tzinfo=utc)

    def __str__(self):
        return self.id

    def __repr__(self):
        return '{operation} token: {id}'.format(operation=self.operation, id=self.id)


class TokenManager:

    def __init__(self, bucket_id):
        self.bucket_id = bucket_id

    def create(self, operation):
        operation = operation.upper()
        assert(operation in ['PUSH', 'PULL'])
        token_json = api_client.create_token(bucket_id=self.bucket_id, operation=operation)
        return Token(token_json)


class File:

    def __init__(self, json_payload):
        self.bucket_id = json_payload['bucket']
        self.hash = json_payload['hash']
        self.content_type = json_payload['mimetype']
        self.name = json_payload['filename']
        self.size = json_payload['size']

    def __str__(self):
        return self.name

    def __repr__(self):
        return '{name} ({size} {content_type})'.format(name=self.name, size=self.size, content_type=self.content_type)

    def download(self):
        return api_client.download_file(bucket_id=self.bucket_id, file_hash=self.hash)

    def delete(self):
        bucket_files = FileManager(bucket_id=self.bucket_id)
        bucket_files.delete(self.hash)


class FileManager:

    def __init__(self, bucket_id):
        self.bucket_id = bucket_id

    def all(self):
        files_json = api_client.get_files(bucket_id=self.bucket_id)
        return [File(payload) for payload in files_json]

    def _upload(self, file):
        api_client.upload_file(bucket_id=self.bucket_id, file=file)

    def upload(self, file):

        # Support path strings as well as file-like objects
        if isinstance(file, str):
            with io.open(file, mode='rb') as file:
                self._upload(file)
        else:
            self._upload(file)

    def download(self, file_id):
        raise NotImplementedError

    def delete(self, file_id):
        raise NotImplementedError
