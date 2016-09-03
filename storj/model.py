# -*- coding: utf-8 -*-
"""Storj model module."""

from datetime import datetime

from pytz import utc
from storj import BucketManager
from storj.api import MetadiskApiError
from storj.sdk import FileManager, BucketKeyManager, TokenManager, ShardManager


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