# -*- coding: utf-8 -*-
"""Storj model module."""

from datetime import datetime

from pytz import utc
from steenzout.object import Object
from storj import BucketManager
from storj.sdk import FileManager, BucketKeyManager, TokenManager, ShardManager


class Bucket(Object):
    """"""

    def __init__(
            self, id=None, name=None, status=None, user=None,
            created=None, storage=None, transfer=None, pubkeys=None):
        self.id = id
        self.name = name
        self.status = status
        self.user = user
        self.storage = storage
        self.transfer = transfer
        self.authorized_public_keys = pubkeys

        self.files = FileManager(bucket_id=self.id)
        self.authorized_public_keys = BucketKeyManager(
            bucket=self, authorized_public_keys=self.authorized_public_keys)
        self.tokens = TokenManager(bucket_id=self.id)

        if created is not None:
            self.created = datetime.strptime(created, '%Y-%m-%dT%H:%M:%S.%fZ').replace(tzinfo=utc)
        else:
            self.created = None

    def __str__(self):
        return self.name

    def __repr__(self):
        return 'Bucket {id} ({name})'.format(id=self.id, name=self.name)

    def delete(self):
        BucketManager.delete(bucket_id=self.id)


class Token(Object):

    def __init__(
            self, token=None, bucket=None, operation=None, expires=None):
        self.id = token
        self.bucket_id = bucket
        self.operation = operation
        self.expires_at = expires

        if expires is not None:
            self.expires = datetime.strptime(expires, '%Y-%m-%dT%H:%M:%S.%fZ').replace(tzinfo=utc)
        else:
            self.expires = None

    def __str__(self):
        return self.id

    def __repr__(self):
        return '{operation} token: {id}'.format(
            operation=self.operation, id=self.id)


class File(Object):

    def __init__(self, bucket=None, hash=None, mimetype=None, filename=None, size=None):
        self.bucket_id = bucket
        self.hash = hash
        self.content_type = mimetype
        self.name = filename
        self.size = size
        self.shardManager = ShardManager()

    def __str__(self):
        return self.name

    def __repr__(self):
        return '{name} ({size} {content_type})'.format(
            name=self.name, size=self.size, content_type=self.content_type)

    def download(self):
        return api_client.download_file(bucket_id=self.bucket_id, file_hash=self.hash)

    def delete(self):
        bucket_files = FileManager(bucket_id=self.bucket_id)
        bucket_files.delete(self.hash)
