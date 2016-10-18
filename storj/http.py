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
from six.moves.urllib.parse import urlencode, urljoin

try:
    from json.decoder import JSONDecodeError
except ImportError:
    # Python 2
    JSONDecodeError = ValueError

from . import model
from .api import ecdsa_to_hex
from .exception import StorjBridgeApiError
from storj import web_socket


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

    logger = logging.getLogger('%s.Client' % __name__)

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
        """(str): user password"""
        return self._password

    @password.setter
    def password(self, value):
        self._password = sha256(value.encode('ascii')).hexdigest()

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
            })

    def _prepare_request(self, **kwargs):

        kwargs.setdefault('headers', {})

        # Add appropriate authentication headers
        if isinstance(self.private_key, SigningKey):
            self._add_ecdsa_signature(kwargs)
        elif self.email and self.password:
            self._add_basic_auth(kwargs)

        # Generate URL from path
        path = kwargs.pop('path')
        assert path.startswith('/')
        kwargs['url'] = urljoin(self.api_url, path)

        return requests.Request(**kwargs).prepare()

    def _request(self, **kwargs):
        """Perform HTTP request.

        Args:
            kwargs (dict): keyword arguments.

        Raises:
            :py:class:`StorjBridgeApiError`: in case::
                - internal server error
                - error attribute is present in the JSON response
                - HTTP response JSON decoding failed
        """

        response = self.session.send(self._prepare_request(**kwargs))
        self.logger.debug('_request response %s', response.text)

        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            self.logger.error(e)
            self.logger.debug('response.text=%s', response.text)
            raise StorjBridgeApiError(response.text)

        # Raise any errors as exceptions
        try:
            if response.text != '':
                response_json = response.json()
            else:
                return {}

            if 'error' in response_json:
                raise StorjBridgeApiError(response_json['error'])

            return response_json

        except JSONDecodeError as e:
            self.logger.error(e)
            self.logger.error('_request body %s', response.text)
            raise StorjBridgeApiError('Could not decode response.')

    def bucket_create(self, name, storage=None, transfer=None):
        """Create storage bucket.

        Args:
            name (str): name.
            storage (int): storage limit (in GB).
            transfer (int): transfer limit (in GB).

        Returns:
            (:py:class:`model.Bucket`): bucket.
        """
        self.logger.info('bucket_create(%s, %s, %s)', name, storage, transfer)

        data = {'name': name}
        if storage:
            data['storage'] = storage
        if transfer:
            data['transfer'] = transfer

        response = self._request(method='POST', path='/buckets', json=data)
        return model.Bucket(**response)

    def bucket_delete(self, bucket_id):
        """Delete a storage bucket.

        Args:
            bucket_id (string): unique identifier.
        """
        self.logger.info('bucket_delete(%s)', bucket_id)
        self._request(method='DELETE', path='/buckets/%s' % bucket_id)

    def bucket_files(self, bucket_id):
        """

        Args:
            bucket_id (string): unique identifier.
        """
        self.logger.info('bucket_files(%s)', bucket_id)

        return self._request(
            method='GET',
            path='/buckets/%s/files/' % (bucket_id),)

    def bucket_get(self, bucket_id):
        """Returns buckets.

        Args:
            bucket_id (str): bucket unique identifier.

        Returns:
            (:py:class:`model.Bucket`): bucket.
        """
        try:
            response = self._request(
                method='GET',
                path='/buckets/%s' % bucket_id)
            return model.Bucket(**response)

        except requests.HTTPError as e:
            if e.response.status_code == requests.codes.not_found:
                return None
            else:
                raise e

    def bucket_list(self):
        """Returns buckets.

        Returns:
            (generator[:py:class:`model.Bucket`]): buckets.
        """
        self.logger.info('bucket_list()')

        response = self._request(method='GET', path='/buckets')

        if response is not None:
            for element in response:
                yield model.Bucket(**element)
        else:
            raise StopIteration

    def bucket_set_keys(self, bucket_id, keys):
        self.logger.info('bucket_set_keys()', bucket_id, keys)

        self._request(
            method='PATCH',
            path='/buckets/%s' % bucket_id,
            json={'pubkeys': keys})

    def contacts_list(self):
        self.logger.info('contacts_list()')

        response = self._request(method='GET', path='/contacts', json={})

        if response is not None:
            return response

    def file_pointers(self, bucket_id, file_id):
        """Get a list of pointers associated with a file.

        Args:
            bucket_id (string): unique identifier.
        """
        self.logger.info('bucket_files(%s, %s)', bucket_id, file_id)

        pull_token = self.token_create(bucket_id, operation='PULL')
        return self._request(
            method='GET',
            path='/buckets/%s/files/%s/' % (bucket_id, file_id),
            headers={'x-token': pull_token['token']})

    def file_download(self, bucket_id, file_id):
        self.logger.info('file_pointers(%s, %s)', bucket_id, file_id)

        pointers = self.file_pointers(
            bucket_id=bucket_id, file_id=file_id)

        file_contents = BytesIO()
        for pointer in pointers:
            ws = web_socket.Client(
                pointer=pointer, file_contents=file_contents)
            ws.connect()
            ws.run_forever()

        return file_contents

    def file_upload(self, bucket_id, file, frame):
        """Upload file.

        Args:
            bucket_id (str):
            file ():
            frame ():
        """
        self.logger.info('upload_file(%s, %s, %s)', bucket_id, file, frame)

        def get_size(file_like_object):
            return os.stat(file_like_object.name).st_size

        file_size = get_size(file)

        # TODO:
        # encrypt file
        # shard file

        push_token = self.token_create(bucket_id, "PUSH")

        self.logger.debug('upload_file() push_token=%s', push_token)

        # upload shards to frame
        # delete encrypted file

        self._request(
            method='POST', path='/buckets/%s/files' % bucket_id,
            # files={'file' : file},
            headers={
                #    'x-token': push_token['token'],
                #    'x-filesize': str(file_size)}
                "frame": frame['id'],
                "mimetype": "text",
                "filename": file.name,
            })

    def file_remove(self, bucket_id, file_id):
        """Delete a file pointer from a specified bucket

        Args:
            bucket_id (str): The ID of the bucket containing the file
            file_id (str): The ID of the file
        """
        self.logger.info('file_remove(%s, %s)', bucket_id, file_id)

        self._request(
            method='DELETE',
            path='/buckets/%s/files/%s' % (bucket_id, file_id))

    def frame_add_shard(self, shard, frame_id):
        self.logger.info('frame_add_shard(%s, %s)', shard, frame_id)

        data = {
            'hash': shard.hash,
            'size': shard.size,
            'index': shard.index,
            'challenges': shard.challenges,
            'tree': shard.tree,
        }

        response = self._request(
            method='PUT',
            path='/frames/%s' % frame_id,
            json=data)

        if response is not None:
            return response

    def frame_create(self):
        """Create a file staging frame.

        See `API frames:
        Creates a new file staging frame
        <https://storj.io/api.html#staging>`

        Returns:

        """
        self.logger.info('frame_create()')

        return self._request(method='POST', path='/frames', json={})

    def frame_delete(self, frame_id):
        """

        Args:
            frame_id (str): unique identifier.
        """
        self.logger.info('frame_delete(%s)', frame_id)

        self._request(
            method='DELETE',
            path='/frames/%s' % frame_id,
            json={'frame_id': frame_id})

    def frame_get(self, frame_id):
        """Return a frame.

        See `API frame:
        Fetches the file staging frame by it's unique ID
        <https://storj.io/api.html>`_

        Args:
            frame_id (str): unique identifier.

        Returns:
            (?):
        """
        self.logger.info('frame_get(%s)', frame_id)

        response = self._request(
            method='GET',
            path='/frames/%s' % frame_id,
            json={'frame_id': frame_id})

        if response is not None:
            return model.Frame(**response)

    def frame_list(self):
        """Returns all open file staging frames.

        Returns:
            (): all open file staging frames.
        """
        self.logger.info('frame_list()')

        response = self._request(
            method='GET',
            path='/frames',
            json={})

        if response is not None:
            return response

    def key_delete(self, key_id):
        self.logger.info('key_delete(%s)', key_id)
        self._request(method='DELETE', path='/keys/%s' % key_id)

    def key_dump(self):
        self.logger.info('key_dump()')

        if (self.private_key is not None and self.public_key is not None):
            print('Local Private Key: ' + self.private_key
                  + '\nLocal Public Key:' + self.public_key)

        keys = self.key_get()

        if not keys:
            print('No keys associated with this account.')
        else:
            print('Public keys for this account: '
                  + str([key['id'] for key in keys]))

    def key_export(self):
        self.logger.info('key_export()')

        print('Writing your public key to file...')
        with open('public.pem', 'wb') as keyfile:
            keyfile.write(self.public_key.to_pem())

        print('Writing private key to file... Keep this secret!')
        with open('private.pem', 'wb') as keyfile:
            keyfile.write(self.private_key.to_pem())

        print('Wrote keyfiles to dir: %s' % os.getcwd())

    def key_generate(self):
        self.logger.info('key_generate()')

        print("This will replace your public and private keys in 3 seconds...")
        time.sleep(3)
        (self.private_key, self.public_key) = storj.generate_new_key_pair()

        s = raw_input('Export keys to file for later use? [Y/N]')
        if 'Y' in s.upper():
            self.key_export()

        self.key_register(self.public_key)

    def key_get(self):
        """Gets all public keys associated with the authenticated account

        Returns:
            (list[dict]): a list of keys
        """
        self.logger.info('key_get()')

        response = self._request(method='GET', path='/keys')

        if response is not None:
            return response

    def key_import(self, private_keyfile_path, public_keyfile_path):
        self.logger.info(
            'key_import(%s, %s)' % (private_keyfile_path, public_keyfile_path))

        with open(public_keyfile_path, 'r') as f:
            self.public_key = VerifyingKey.from_pem(f.read())

        with open(private_keyfile_path, 'r') as f:
            self.private_key = SigningKey.from_pem(f.read())

        self.key_register(self.public_key)

    def key_register(self, public_key):
        self.logger.info('key_register(%s)', public_key)

        response = self._request(
            method='POST',
            path='/keys',
            json={'key': ecdsa_to_hex(public_key)})

        if response is not None:
            return response

    def token_create(self, bucket_id, operation):
        """Create upload token.

        Args:
            bucket_id (str): bucket unique identifier.
            operation ():

        Returns:
            (dict[]):
        """
        self.logger.info('create_token(%s, %s)', bucket_id, operation)

        return self._request(
            method='POST',
            path='/buckets/%s/tokens' % bucket_id,
            json={'operation': operation})

    def user_create(self, email, password):
        """Create a new user with specified email and password.

        Args:
            email (str): The new user's email address.
            password (str): The new user's password
        """
        self.logger.info('user_create(%s, %s)', email, password)

        password = sha256(password).hexdigest()

        self._request(
            method='POST',
            path='/users',
            json={'email': email, 'password': password})

        self.authenticate(email=email, password=password)
