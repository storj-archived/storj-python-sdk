# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import os
import time
import json
from binascii import b2a_hex
from base64 import b64encode
from hashlib import sha256
from io import BytesIO

try:
    from json.decoder import JSONDecodeError
except ImportError:
    # Python 2
    JSONDecodeError = ValueError

try:
    from urllib.parse import urljoin, urlencode
except ImportError:
    # Python 2
    from urllib import urlencode
    from urlparse import urljoin

import requests
from requests import Request
from ecdsa import SigningKey
from ecdsa.util import sigencode_der
from ws4py.client.threadedclient import WebSocketClient


def ecdsa_to_hex(ecdsa_key):
    return '04' + b2a_hex(ecdsa_key.to_string()).decode('ascii')


class MetadiskApiError(Exception):
    pass


class MetadiskClient:

    def __init__(self):
        self.api_url = 'https://api.storj.io/'
        self.session = requests.Session()
        self.email = None
        self.password = None
        self.private_key = None
        self.public_key = None
        self.public_key_hex = None

    def authenticate(self, email=None, password=None, ecdsa_private_key=None):
        if email and password:
            self.email = email
            self.password = password
        if isinstance(ecdsa_private_key, SigningKey):
            self.private_key = ecdsa_private_key
            self.public_key = self.private_key.get_verifying_key()
            self.public_key_hex = ecdsa_to_hex(self.public_key)

    def _add_basic_auth(self, request_kwargs):

        email_and_password = self.email + ':' + self.password
        request_kwargs['headers'].update(
            {
                'Authorization': b'Basic ' + b64encode(email_and_password.encode('ascii')),
            }
        )

    def _add_ecdsa_signature(self, request_kwargs):

        method = request_kwargs.get('method', 'GET')

        if method in ('GET', 'DELETE'):
            request_kwargs.setdefault('params', {})
            request_kwargs['params']['__nonce'] = int(time.time())
            data = urlencode(request_kwargs['params'])
        else:
            request_kwargs.setdefault('json', {})
            request_kwargs['json']['__nonce'] = int(time.time())
            data = json.dumps(request_kwargs['json'])

        contract = '\n'.join((method, request_kwargs['path'], data)).encode('utf-8')
        signature_bytes = self.private_key.sign(contract, sigencode=sigencode_der, hashfunc=sha256)
        signature = b2a_hex(signature_bytes).decode('ascii')

        request_kwargs['headers'].update(
            {
                'x-signature': signature,
                'x-pubkey': ecdsa_to_hex(self.public_key),
            }
        )

    def prepare_request(self, **kwargs):

        kwargs.setdefault('headers', {})

        # Add appropriate authentication headers
        if isinstance(self.private_key, SigningKey):
            self._add_ecdsa_signature(kwargs)
        elif self.email and self.password:
            self._add_basic_auth(kwargs)

        # Generate URL from path
        path = kwargs.pop('path')
        assert(path.startswith('/'))
        kwargs['url'] = urljoin(self.api_url, path)

        return Request(**kwargs).prepare()

    def request(self, **kwargs):

        # Prepare and send the request
        request = self.prepare_request(**kwargs)
        response = self.session.send(request)

        # Raise any errors as exceptions
        try:
            response_json = response.json()
        except JSONDecodeError:
            pass
        else:
            if 'error' in response_json:
                raise MetadiskApiError(response_json['error'])

        response.raise_for_status()

        return response

    def register_user(self, email, password):

        data = {
            'email': email,
            'password': password
        }

        response = self.request(
            method='POST',
            path='/users',
            json=data,
        )

        assert(response.status_code == 200)

        self.authenticate(email=email, password=password)

    def register_ecdsa_key(self, public_key):

        data = {
            'key': public_key,
        }

        response = self.request(
            method='POST',
            path='/keys',
            json=data,
        )

        return response.json()

    def get_keys(self):
        response = self.request(method='GET', path='/keys')
        return response.json()

    def delete_key(self, key):
        response = self.request(method='DELETE', path='/keys/' + key)
        assert(response.status_code == 200)

    def create_token(self, bucket_id, operation):
        data = {
            'operation': operation,
        }
        response = self.request(
            method='POST',
            path='/buckets/{id}/tokens'.format(id=bucket_id),
            json=data,
        )
        return response.json()

    def upload_file(self, bucket_id, file):

        def get_size(file_like_object):
            old_position = file_like_object.tell()
            file_like_object.seek(0, os.SEEK_END)
            size = file_like_object.tell()
            file_like_object.seek(old_position, os.SEEK_SET)
            return size

        file_size = get_size(file)

        push_token = self.create_token(bucket_id, operation='PUSH')

        response = self.request(
            method='PUT',
            path='/buckets/{id}/files'.format(id=bucket_id),
            files={
                'data': file,
            },
            headers={
                'x-token': push_token['token'],
                'x-filesize': str(file_size),
            }
        )

        assert(response.status_code == 200)

    def get_files(self, bucket_id):
        response = self.request(
            method='GET',
            path='/buckets/{id}/files'.format(id=bucket_id),
        )
        return response.json()

    def get_file_pointers(self, bucket_id, file_hash):

        pull_token = self.create_token(bucket_id, operation='PULL')
        response = self.request(
            method='GET',
            path='/buckets/{id}/files/{hash}'.format(id=bucket_id, hash=file_hash),
            headers={
                'x-token': pull_token['token'],
            }
        )
        return response.json()

    def download_file(self, bucket_id, file_hash):

        pointers = self.get_file_pointers(bucket_id=bucket_id, file_hash=file_hash)

        file_contents = BytesIO()
        for pointer in pointers:
            ws = FileRetrieverWebSocketClient(pointer=pointer, file_contents=file_contents)
            ws.connect()
            ws.run_forever()

        return file_contents

    def get_buckets(self):
        response = self.request(method='GET', path='/buckets')
        return response.json()

    def get_bucket(self, bucket_id):
        response = self.request(
            method='GET',
            path='/buckets/{id}'.format(id=bucket_id),
        )
        return response.json()

    def delete_bucket(self, bucket_id):
        response = self.request(
            method='DELETE',
            path='/buckets/{id}'.format(id=bucket_id),
        )
        assert(response.status_code == 200)

    def create_bucket(self, bucket_name, storage_limit=None, transfer_limit=None):

        data = {
            'name': bucket_name,
        }

        if storage_limit:
            data['storage'] = storage_limit

        if transfer_limit:
            data['transfer'] = transfer_limit

        response = self.request(
            method='POST',
            path='/buckets',
            json=data,
        )

        return response.json()

    def set_bucket_pubkeys(self, bucket_id, keys):

        data = {
            'pubkeys': keys,
        }

        response = self.request(
            method='PATCH',
            path='/buckets/{id}'.format(id=bucket_id),
            json=data,
        )

        assert(response.status_code == 200)


api_client = MetadiskClient()


class FileRetrieverWebSocketClient(WebSocketClient):

    def __init__(self, pointer, file_contents):
        assert isinstance(pointer, dict)
        channel = pointer.pop('channel')
        self.json = pointer
        self.file_contents = file_contents
        super(FileRetrieverWebSocketClient, self).__init__(channel)

    def opened(self):
        self.send(json.dumps(self.json))

    def closed(self, code, reason=None):
        print("Closed websocket", code, reason)

    def received_message(self, m):
        if m.is_binary:
            self.file_contents.write(m.data)
