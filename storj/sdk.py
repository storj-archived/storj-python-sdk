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
        buckets_json = BucketManager.client.get_buckets()
        return [Bucket(payload) for payload in buckets_json]

    @staticmethod
    def get(bucket_id):
        bucket_json = BucketManager.client.get_bucket(bucket_id=bucket_id)
        return Bucket(bucket_json)

    @staticmethod
    def create(name, storage_limit=None, transfer_limit=None):
        bucket_json = BucketManager.client.create_bucket(
            name=name,
            storage=storage_limit,
            transfer=transfer_limit,
        )
        return Bucket(bucket_json)

    @staticmethod
    def delete(bucket_id):
        BucketManager.client.delete_bucket(bucket_id=bucket_id)


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
        api_client.set_bucket_pubkeys(
            bucket_id=self.bucket.id,
            keys=self._authorized_public_keys)

    def remove(self, key):

        if not isinstance(key, str):
            key = ecdsa_to_hex(key)

        self._authorized_public_keys.remove(key)
        api_client.set_bucket_pubkeys(
            bucket_id=self.bucket.id,
            keys=self._authorized_public_keys)

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


class TokenManager:

    def __init__(self, bucket_id):
        self.bucket_id = bucket_id

    def create(self, operation):
        operation = operation.upper()
        assert(operation in ['PUSH', 'PULL'])
        token_json = api_client.create_token(
            bucket_id=self.bucket_id, operation=operation)
        return Token(token_json)


class FileManager:

    def __init__(self, bucket_id):
        self.bucket_id = bucket_id

    def all(self):
        files_json = api_client.get_files(bucket_id=self.bucket_id)
        return [File(payload) for payload in files_json]

    def _upload(self, file, frame):
        api_client.upload_file(bucket_id=self.bucket_id, file=file, frame=frame)

    def upload(self, file, frame):

        # Support path strings as well as file-like objects
        if isinstance(file, str):
            with io.open(file, mode='rb') as file:
                self._upload(file, frame)
        else:
            self._upload(file, frame)

    def download(self, file_id):
        api_client.download_file(self, bucket_id, file_hash)

    def delete(self, file_id):
        raise NotImplementedError


def hash160(data):
    """hex encode returned str"""
    return binascii.hexlify(ripemd160(hashlib.sha256(data).digest()))


def ripemd160(data):
    return hashlib.new('ripemd160', data).digest()


BS = 16


def pad(s):
    return s + (BS - len(s) % BS) * chr(BS - len(s) % BS)


def unpad(s):
    return s[:-ord(s[len(s)-1:])]
