# -*- coding: utf-8 -*-

from __future__ import unicode_literals


import binascii
import hashlib
import io
import random
import string

from datetime import datetime

from pytz import utc
from hashlib import sha256

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
                'Field "{field}" not present in JSON payload'.format(
                    field=e.args[0]))

        self.files = FileManager(bucket_id=self.id)
        self.authorized_public_keys = BucketKeyManager(
            bucket=self, authorized_public_keys=self.authorized_public_keys)
        self.tokens = TokenManager(bucket_id=self.id)
        self.created_at = datetime.strptime(
            self.created_at, '%Y-%m-%dT%H:%M:%S.%fZ').replace(tzinfo=utc)

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


class Token:

    def __init__(self, json_payload):
        self.id = json_payload['token']
        self.bucket_id = json_payload['bucket']
        self.operation = json_payload['operation']
        self.expires_at = json_payload['expires']
        self.expires_at = datetime.strptime(
            self.expires_at, '%Y-%m-%dT%H:%M:%S.%fZ').replace(tzinfo=utc)

    def __str__(self):
        return self.id

    def __repr__(self):
        return '{operation} token: {id}'.format(
            operation=self.operation, id=self.id)


class TokenManager:

    def __init__(self, bucket_id):
        self.bucket_id = bucket_id

    def create(self, operation):
        operation = operation.upper()
        assert(operation in ['PUSH', 'PULL'])
        token_json = api_client.create_token(
            bucket_id=self.bucket_id, operation=operation)
        return Token(token_json)


class File:

    def __init__(self, json_payload):
        self.bucket_id = json_payload['bucket']
        self.hash = json_payload['hash']
        self.content_type = json_payload['mimetype']
        self.name = json_payload['filename']
        self.size = json_payload['size']
        self.shardManager = ShardManager()

    def __str__(self):
        return self.name

    def __repr__(self):
        return '{name} ({size} {content_type})'.format(
            name=self.name, size=self.size, content_type=self.content_type)

    def download(self):
        return api_client.download_file(
            bucket_id=self.bucket_id, file_hash=self.hash)

    def delete(self):
        bucket_files = FileManager(bucket_id=self.bucket_id)
        bucket_files.delete(self.hash)


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
        raise NotImplementedError

    def delete(self, file_id):
        raise NotImplementedError


class ShardManager:

    def __init__(self, filepath, shard_size):
        self.shards = []
        self.challenges = 8
        self.shard_index = 0
        self.index = 0
        self.shard_size = shard_size
        self.filepath = filepath

        file = open(filepath, "rb")

        while(True):
            chunk = file.read(shard_size)
            if not chunk:
                break
            tmpfile = open("C:/test/shard"+str(self.index)+".shard", "wb")
            tmpfile.write(chunk)
            tmpfile.close()

            shard = Shard()
            shard.setSize(shard_size)
            shard.setHash(self.hash160(chunk))
            self.addChallenges(shard, chunk)
            shard.setIndex(self.index)
            self.index += 1
            self.shards.append(shard)

    def addChallenges(self, shard, shardData, numberOfChallenges=12):
        for i in xrange(numberOfChallenges):
            challenge = self.getRandomChallengeString()

            data2hash = binascii.hexlify(str(challenge + shardData))  # concat and hex-encode data

            tree = binascii.hexlify(self.hash160(self.hash160(data2hash)))  # double hash160 the data

            shard.addChallenge(challenge)
            shard.addTree(tree)

    def getRandomChallengeString(self):
        return ''.join(random.choice(string.ascii_letters) for _ in xrange(32))

    def hash160(self, data):
        """hex encode returned str"""
        return binascii.hexlify(self.ripemd160(hashlib.sha256(data).hexdigest()))

    def ripemd160(self, data):
        return hashlib.new('ripemd160', data).hexdigest()


class Shard:

    def __init__(self):
        self.id = None
        self.tree = []
        self.challenges = []
        self.path = None
        self.hash = None
        self.size = None
        self.index = None

    def all(self):
        return 'Shard{index=%s, hash=%s, size=%s, tree={%s}, challenges={%s}' % (
            self.index, self.hash, self.size,
            ', '.join(self.tree),
            ', '.join(self.challenges)
        )

    def setPath(self, path):
        self.path = path

    def set_id(self, id):
        self.id = id

    def setIndex(self, index):
        self.index = index

    def setHash(self, hash):
        self.hash = hash

    def setSize(self, size):
        self.size = size

    def setTree(self, tree):
        self.tree = tree

    def setChallenges(self, challenges):
        self.challenges = challenges

    def addChallenge(self, challenge):
        self.challenges.append(challenge)

    def addTree(self, tree):
        self.tree.append(tree)
