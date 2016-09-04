# -*- coding: utf-8 -*-
"""Storj HTTP module."""

import os

import logging
import json
import requests
import storj
import time

from base64 import b64encode
from binascii import b2a_hex
from ecdsa import SigningKey
from hashlib import sha256
from io import BytesIO
from urllib import urlencode
from urlparse import urljoin

from . import model
from .api import ecdsa_to_hex, JSONDecodeError
from .exception import MetadiskApiError
from .web_socket import Client


class Client(object):
    """

    Attributes:
        api_url (str): the Storj API endpoint.
        session ():
        email (str): user email address.
        password (str): user password.
        private_key ():
        public_key ():
        public_key_hex ():
    """

    logger = logging.getLogger(Client.__name__)

    def __init__(self, email, password):
        self.api_url = 'https://api.storj.io/'
        self.session = requests.Session()
        self.email = email
        self.password = password
        self.private_key = None
        self.public_key = None
        self.public_key_hex = None

    @property
    def password(self):
        """(str):"""
        return self._password

    @password.setter
    def password(self, value):
        self._password = sha256(value).hexdigest()

    def authenticate(self, ecdsa_private_key=None):
        self.logger.debug('authenticate')

        if isinstance(ecdsa_private_key, SigningKey):
            self.private_key = ecdsa_private_key
            self.public_key = self.private_key.get_verifying_key()
            self.public_key_hex = ecdsa_to_hex(self.public_key)

    def _add_basic_auth(self, request_kwargs):
        self.logger.debug('using basic auth')

        request_kwargs['headers'].update({
            'Authorization': b'Basic %s' % b64encode(
                ('%s:%s' % (self.email, self.password)).encode('ascii')
            ),
        })

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

        contract = '\n'.join(
            (method, request_kwargs['path'], data)).encode('utf-8')
        signature_bytes = self.private_key.sign(
            contract, sigencode=sigencode_der, hashfunc=sha256)
        signature = b2a_hex(signature_bytes).decode('ascii')

        request_kwargs['headers'].update(
            {
                'x-signature': signature,
                'x-pubkey': ecdsa_to_hex(self.public_key),
            }
        )

    def create_bucket(self, name, storage=None, transfer=None):
        """Create storage bucket.

        Args:
            name (str): name.
            storage (int): storage limit (in GB).
            transfer (int): transfer limit (in GB).
        """

        data = {'name': name}

        if storage:
            data['storage'] = storage

        if transfer:
            data['transfer'] = transfer

        self.request(method='POST', path='/buckets', json=data)

    def generate_new_key_pair(self):
        print("This will replace your public and private keys in 3 seconds...")
        time.sleep(3)
        (self.private_key, self.public_key) = storj.generate_new_key_pair()

        s = raw_input('Export keys to file for later use? [Y/N]')
        if('Y' in s.upper()):
            self.export_keys()

        self.register_ecdsa_key(self.public_key)

    def get_bucket(self, bucket_id):
        """Returns buckets.

        Args:
            bucket_id (str): bucket unique identifier.

        Returns:
            (:py:class:`model.Bucket`): bucket.
        """
        response = self.request(method='GET', path='/buckets/%s' % bucket_id)

        if response is not None:
            return model.Bucket(**response)

    def get_buckets(self):
        """Returns buckets.

        Returns:
            (array[:py:class:`model.Bucket`]): buckets.
        """
        self.logger.debug('get_buckets()')

        response = self.request(method='GET', path='/buckets')

        for element in response:
            yield model.Bucket(**element)

    def export_keys(self):
        print("Writing your public key to file...")
        with open('public.pem', 'wb') as keyfile:
            keyfile.write(self.public_key.to_pem())

        print("Writing private key to file... Keep this secret!")
        with open('private.pem', 'wb') as keyfile:
            keyfile.write(self.private_key.to_pem())

        print("Wrote keyfiles to dir: " + os.getcwd())

    def import_keys(self, private_keyfile_path, public_keyfile_path):
        with open(public_keyfile_path, 'r') as f:
            self.public_key = VerifyingKey.from_pem(f.read())

        with open(private_keyfile_path, 'r') as f:
            self.private_key = SigningKey.from_pem(f.read())

        self.register_ecdsa_key(self.public_key)

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

        return requests.Request(**kwargs).prepare()

    def request(self, **kwargs):
        """Perform HTTP request.

        Args:
            kwargs (dict): keyword arguments.
        """

        response = self.session.send(self.prepare_request(**kwargs))

        # Raise any errors as exceptions
        try:
            response.raise_for_status()
            response_json = response.json()
            self.logger.debug('response json %s', response_json)

            if 'error' in response_json:
                raise MetadiskApiError(response_json['error'])

            return response_json

        except JSONDecodeError as e:
            self.logger.error('request %s', e)
            raise e

    def register_user(self, email, password):

        password = sha256(password).hexdigest()

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
            'key': ecdsa_to_hex(public_key),
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

    def dump_keys(self):
        if(self.private_key is not None and self.public_key is not None):
            print("Local Private Key: " + self.private_key +
                  "Local Public Key:" + self.public_key)
        if(self.get_keys() is not []):
            print("Public keys for this account: " + str([key['id'] for key in self.get_keys()]))
        else:
            print("No keys associated with this account.")

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

    def upload_file(self, bucket_id, file, frame):

        def get_size(file_like_object):
            old_position = file_like_object.tell()
            file_like_object.seek(0, os.SEEK_END)
            size = file_like_object.tell()
            file_like_object.seek(old_position, os.SEEK_SET)
            return size

        file_size = get_size(file)

        push_token = self.create_token(bucket_id, operation='PUSH')

        response = self.request(
            method='POST',
            path='/buckets/{id}/files'.format(id=bucket_id),
            files={
                'frame': frame,
                'mimetype': "text",  # TODO: Change this after testing
                'filename': "test.txt"
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
            path='/buckets/{id}/files/{hash}'.format(
                id=bucket_id, hash=file_hash
            ),
            headers={
                'x-token': pull_token['token'],
            }
        )
        return response.json()

    def download_file(self, bucket_id, file_hash):

        pointers = self.get_file_pointers(
            bucket_id=bucket_id, file_hash=file_hash)

        file_contents = BytesIO()
        for pointer in pointers:
            ws = Client(
                pointer=pointer, file_contents=file_contents)
            ws.connect()
            ws.run_forever()

        return file_contents

    def delete_bucket(self, bucket_id):
        response = self.request(
            method='DELETE',
            path='/buckets/{id}'.format(id=bucket_id),
        )
        assert(response.status_code == 200)

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

    def create_frame(self):

        data = {}

        response = self.request(
            method='POST',
            path='/frames',
            json=data,
        )

        assert(response.status_code == 200)

        return response.json()

    def get_frame(self, frame_id):
        data = {
            'frame_id': frame_id,
        }

        response = self.request(
            method='GET',
            path='/frames/{id}'.format(id=frame_id),
            json=data,
        )

        assert(response.status_code == 200)

        return response.json()

    def get_all_frames(self):
        data = {}

        response = self.request(
            method='GET',
            path='/frames',
            json=data,
        )

        assert(response.status_code == 200)

        return response.json()

    def delete_frame(self, frame_id):
        data = {
            'frame_id': frame_id,
        }

        response = self.request(
            method='DELETE',
            path='/frames/{id}'.format(id=frame_id),
            json=data,
        )

        assert(response.status_code == 204)

    def list_contacts(self):
        data = {
        }

        response = self.request(
            method='GET',
            path='/contacts',
            json=data,
        )

        return response.json()

    def add_shard_to_frame(self, shard, frame_id):
        data = {
            'hash': shard.hash,
            'size': shard.size,
            'index': shard.index,
            'challenges': shard.challenges,
            'tree': shard.tree,
        }

        response = self.request(
            method="PUT",
            path='/frames/{id}'.format(id=frame_id),
            json=data,
        )

        return response
