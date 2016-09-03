# -*- coding: utf-8 -*-
"""Storj model module."""

from datetime import datetime

from pytz import utc
from steenzout.object import Object
from storj import BucketManager
from storj.sdk import FileManager, BucketKeyManager, TokenManager, ShardManager


class Bucket(Object):
    """

    Attributes:
        id ():
        name ():
        status ():
        user ():
        created ():
        storage ():
        transfer ():
        pubkeys ():
    """

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
    """

    Attributes:
        token ():
        bucket ():
        operation ():
        expires ():
    """

    def __init__(
            self, token=None, bucket=None, operation=None, expires=None):
        self.id = token
        self.bucket_id = bucket
        self.operation = operation

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
    """
    Attributes:
        bucket ():
        hash ():
        mimetype ():
        filename ():
        size ():
        shardManager ():
    """

    def __init__(self, bucket=None, hash=None, mimetype=None, filename=None, size=None):
        self.bucket = bucket
        self.hash = hash
        self.mimetype = mimetype
        self.filename = filename
        self.size = size
        self.shardManager = ShardManager()

    @property
    def content_type(self):
        return self.mimetype

    @property
    def name(self):
        return self.filename

    def __str__(self):
        return self.filename

    def __repr__(self):
        return '{name} ({size} {content_type})'.format(
            name=self.filename, size=self.size, content_type=self.mimetype)

    def download(self):
        return api_client.download_file(bucket_id=self.bucket, file_hash=self.hash)

    def delete(self):
        bucket_files = FileManager(bucket_id=self.bucket)
        bucket_files.delete(self.hash)
