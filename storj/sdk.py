# -*- coding: utf-8 -*-

import binascii
import hashlib
import io

from .api import ecdsa_to_hex
from .http import Client
from .model import Bucket, Token, File


class BucketManager:

    client = Client()

    @staticmethod
    def all():
        buckets_json = BucketManager.client.bucket_list()
        return [Bucket(payload) for payload in buckets_json]

    @staticmethod
    def get(bucket_id):
        bucket_json = BucketManager.client.bucket_get(bucket_id=bucket_id)
        return Bucket(bucket_json)

    @staticmethod
    def create(name, storage_limit=None, transfer_limit=None):
        bucket_json = BucketManager.client.bucket_create(
            name=name,
            storage=storage_limit,
            transfer=transfer_limit,
        )
        return Bucket(bucket_json)

    @staticmethod
    def delete(bucket_id):
        BucketManager.client.bucket_delete(bucket_id=bucket_id)


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
        api_client.bucket_set_keys(
            bucket_id=self.bucket.id,
            keys=self._authorized_public_keys)

    def remove(self, key):

        if not isinstance(key, str):
            key = ecdsa_to_hex(key)

        self._authorized_public_keys.remove(key)
        api_client.bucket_set_keys(
            bucket_id=self.bucket.id,
            keys=self._authorized_public_keys)

    def clear(self):
        self._authorized_public_keys = []
        api_client.bucket_set_keys(bucket_id=self.bucket.id, keys=[])


class UserKeyManager:

    @staticmethod
    def all():
        keys_json = api_client.key_get()
        return [payload['key'] for payload in keys_json]

    @staticmethod
    def add(key):

        if not isinstance(key, str):
            key = ecdsa_to_hex(key)

        api_client.key_register(key)

    @staticmethod
    def remove(key):

        if not isinstance(key, str):
            key = ecdsa_to_hex(key)

        api_client.key_delete(key)

    @staticmethod
    def clear():
        for key in UserKeyManager.all():
            UserKeyManager.remove(key)


class TokenManager:

    def __init__(self, bucket_id):
        self.bucket_id = bucket_id

    def create(self, operation):
        operation = operation.upper()
        assert(operation in ['PUSH', 'PULL'])
        token_json = api_client.token_create(
            bucket_id=self.bucket_id, operation=operation)
        return Token(token_json)


class FileManager:

    def __init__(self, bucket_id):
        self.bucket_id = bucket_id

    def all(self):
        files_json = api_client.file_list(bucket_id=self.bucket_id)
        return [File(payload) for payload in files_json]

    def _upload(self, file, frame):
        api_client.file_upload(bucket_id=self.bucket_id,
                               file=file, frame=frame)

    def upload(self, file, frame):

        # Support path strings as well as file-like objects
        if isinstance(file, str):
            with io.open(file, mode='rb') as file:
                self._upload(file, frame)
        else:
            self._upload(file, frame)

    def download(self, file_id):
        api_client.file_download(self, bucket_id, file_hash)

    def delete(self, bucket_id, file_id):
        api_client.file_remove(self, bucket_id, file_id)
