# -*- coding: utf-8 -*-
"""Storj HTTP module."""

import os

import logging
import json
import requests
import time

from base64 import b64encode
from binascii import b2a_hex

from ecdsa import SigningKey, SECP256k1, VerifyingKey
from ecdsa.util import sigencode_der
from hashlib import sha256
from io import BytesIO
from six.moves.urllib.parse import urlencode, urljoin

try:
    from json.decoder import JSONDecodeError
except ImportError:
    # Python 2
    JSONDecodeError = ValueError

from api import ecdsa_to_hex
from exception import BridgeError, ClientError

from . import web_socket
from . import model


__logger = logging.getLogger(__name__)


def handle_nonhttp_errors(func):
    """Handle non-HTTP errors."""
    def decorator(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except requests.exceptions.RequestException as e:
            __logger.error('Failed to contact the bridge: %s', e)
            raise ClientError(message='Failed to contact the bridge')
    return decorator


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
        timeout (float or tuple): (optional) how long to wait for the server to
            send data before giving up, as a float, or
            a (connect timeout, read timeout) tuple.
    """

    logger = logging.getLogger('%s.Client' % __name__)

    def __init__(self, email, password, do_hashing=True, timeout=None):
        self.api_url = 'https://api.storj.io/'
        self.session = requests.Session()
        self.email = email
        self.do_hashing = do_hashing
        self.password = password
        self.private_key = None
        self.public_key = None
        self.public_key_hex = None
        self.timeout = timeout

    @property
    def password(self):
        """(str): user password"""
        return self._password

    @password.setter
    def password(self, value):
        if self.do_hashing:
            self._password = sha256(value.encode('ascii')).hexdigest()
        else:
            self._password = value

    def authenticate(self, ecdsa_private_key=None):
        self.logger.debug('authenticate')

        if isinstance(ecdsa_private_key, SigningKey):
            self.private_key = ecdsa_private_key
            self.public_key = self.private_key.get_verifying_key()
            self.public_key_hex = ecdsa_to_hex(self.public_key.to_string())

    def _add_basic_auth(self, request_kwargs):
        self.logger.debug('using basic auth')

        request_kwargs['headers'].update({
            'Authorization': b'Basic ' + b64encode(
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
                'x-pubkey': ecdsa_to_hex(self.public_key.to_string()),
            })

    def _prepare_request(self, **kwargs):
        """Prepares a HTTP request.
        Args:
            kwargs (dict): keyword arguments for the authentication function
                (``_add_ecdsa_signature()`` or ``_add_basic_auth()``) and
                :py:class:`requests.Request` class.
        Raises:
            AssertionError: in case ``kwargs['path']`` doesn't start with ``/``.
        """

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
            :py:class:`BridgeError`: in case::
                - internal server error
                - error attribute is present in the JSON response
                - HTTP response JSON decoding failed
        """

        response = self.session.send(
            self._prepare_request(**kwargs),
            timeout=self.timeout)
        self.logger.debug('_request response %s', response.text)

        try:
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            self.logger.error(e)
            self.logger.debug('response.text=%s', response.text)
            raise BridgeError(response.text)

        # Raise any errors as exceptions
        try:
            if response.text != '':
                response_json = response.json()
            else:
                return {}

            if 'error' in response_json:
                raise BridgeError(response_json['error'])

            return response_json

        except JSONDecodeError as e:
            self.logger.error(e)
            self.logger.error('_request body %s', response.text)
            raise BridgeError('Could not decode response.')

    @handle_nonhttp_errors
    def bucket_create(self, name, storage=None, transfer=None):
        """Create storage bucket.
        See `API buckets: POST /buckets
        <https://storj.github.io/bridge/#!/buckets/post_buckets>`_
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

        return model.Bucket(**self._request(method='POST', path='/buckets', json=data))

    @handle_nonhttp_errors
    def bucket_delete(self, bucket_id):
        """Destroy a storage bucket.
        See `API buckets: DELETE /buckets/{id}
        <https://storj.github.io/bridge/#!/buckets/delete_buckets_id>`_
        Args:
            bucket_id (string): unique identifier.
        """
        self.logger.info('bucket_delete(%s)', bucket_id)
        self._request(method='DELETE', path='/buckets/%s' % bucket_id)

    @handle_nonhttp_errors
    def bucket_files(self, bucket_id):
        """List all the file metadata stored in the bucket.
        See `API buckets: GET /buckets/{id}/files
        <https://storj.github.io/bridge/#!/buckets/get_buckets_id_files>`_
        Args:
            bucket_id (string): unique identifier.
        Returns:
            (dict): to be changed to model in the future.
        """
        self.logger.info('bucket_files(%s)', bucket_id)

        return self._request(
            method='GET',
            path='/buckets/%s/files/' % (bucket_id), )

    @handle_nonhttp_errors
    def bucket_get(self, bucket_id):
        """Return the bucket object.
        See `API buckets: GET /buckets
        <https://storj.github.io/bridge/#!/buckets/get_buckets_id>`_
        Args:
            bucket_id (str): bucket unique identifier.
        Returns:
            (:py:class:`model.Bucket`): bucket.
        """
        self.logger.info('bucket_get(%s)', bucket_id)

        try:
            return model.Bucket(**self._request(
                method='GET',
                path='/buckets/%s' % bucket_id))

        except requests.HTTPError as e:
            if e.response.status_code == requests.codes.not_found:
                return None
            else:
                self.logger.error('bucket_get() error=%s', e)
                raise BridgeError()

    @handle_nonhttp_errors
    def bucket_list(self):
        """List all of the buckets belonging to the user.
        See `API buckets: GET /buckets
        <https://storj.github.io/bridge/#!/buckets/get_buckets>`_
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

    @handle_nonhttp_errors
    def bucket_set_keys(self, bucket_id, bucket_name, keys):
        """Update the bucket with the given public keys.
        See `API buckets: PATCH /buckets/{bucket_id}
        <https://storj.github.io/bridge/#!/buckets/patch_buckets_id>`_
        Args:
            bucket_id (str): bucket unique identifier.
            bucket_name (str): bucket name.
            keys (list[str]): public keys.
        Returns:
            (:py:class:`storj.model.Bucket`): updated bucket information.
        """
        self.logger.info('bucket_set_keys(%s, %s)', bucket_name, keys)

        return model.Bucket(**self._request(
            method='PATCH',
            path='/buckets/%s' % bucket_id,
            json={
                'name': bucket_name,
                'pubkeys': keys}))

    @handle_nonhttp_errors
    def bucket_set_mirrors(self, bucket_id, file_id, redundancy):
        """Establishes a series of mirrors for the given file.
        See `API buckets: POST /buckets/{id}/mirrors
        <https://storj.github.io/bridge/#!/buckets/post_buckets_id_mirrors>`_
        Args:
            bucket_id (str): bucket unique identifier.
            file_id (str): file unique identitifer.
            redundancy (int): number of replicas.
        Returns:
            (:py:class:`storj.model.Mirror`): the mirror settings.
        """
        self.logger.info('bucket_set_mirrors(%s, %s, %s)', bucket_id, file_id, redundancy)

        return model.Mirror(**self._request(
            method='POST',
            path='/buckets/%s/mirrors' % bucket_id,
            json={
                'file': file_id,
                'redundancy': redundancy
            }))

    @handle_nonhttp_errors
    def contact_list(self, page=1, address=None, protocol=None, user_agent=None, connected=None):
        """Lists contacts.
        See `API contacts: GET /contacts
        <https://storj.github.io/bridge/#!/contacts/get_contacts>`_
        Args:
            page (str): pagination indicator.
            address (str): hostname or IP address.
            protocol (str): SemVer protocol tag.
            user_agent (str): Storj user agent string for farming client.
            connected (bool): filter results by connection status.
        Returns:
            (list[:py:class:`storj.model.Contact`]): list of contacts.
        """
        self.logger.info('contacts_list()')

        response = self._request(
            method='GET',
            path='/contacts')

        if response is not None:
            for kwargs in response:
                yield model.Contact(**kwargs)
        else:
            raise StopIteration

    @handle_nonhttp_errors
    def contact_lookup(self, node_id):
        """Lookup for contact information of a node.
        See `API contacts: GET /contacts/{nodeID}
        <https://storj.github.io/bridge/#!/contacts/get_contacts_nodeID>`_
        Args:
            node_id (str): node unique identifier.
        Returns:
            (:py:class:`storj.model.Contact`): contact information
        """
        self.logger.info('contact_lookup(%s)', node_id)

        return model.Contact(**self._request(
            method='GET',
            path='/contacts/%s' % node_id))

    @handle_nonhttp_errors
    def file_pointers(self, bucket_id, file_id, skip, limit, exclude=None):
        """Get list of pointers associated with a file.

        See `API buckets: GET /buckets/{id}/files/{file_id}
        <https://storj.github.io/bridge/#!/buckets/get_buckets_id_files_file_id>`_

        Args:
            bucket_id (str): bucket unique identifier.
            file_id (str): file unique identifier.
            skip (str): pointer index to start the file slice.
            limit (str): number of pointers to resolve tokens for.
            exclude (list[str]): separated list of farmer node unique identifiers to exclude from token retrieval.

        Returns:
            (generator[:py:class:`storj.model.FilePointer`]): file pointers.
        """
        self.logger.debug('bucket_files(%s, %s, %s, %s, %s)', bucket_id, file_id, skip, limit, exclude)

        if bucket_id is None:
            raise ValueError('bucket unique identifier is None')
        if file_id is None:
            raise ValueError('file unique identifier is None')
        if skip is None:
            raise ValueError('starting pointer index is None')
        if limit is None:
            raise ValueError('number of tokens to resolve is None')

        pull_token = self.token_create(bucket_id, operation='PULL')
        exclude = ','.join(exclude or [])

        return self._request(
            method='GET',
            path='/buckets/%s/files/%s/?skip=%s&limit=%s&exclude=%s' % (bucket_id, file_id, skip, limit, exclude),
            headers={'x-token': pull_token.id})

    @handle_nonhttp_errors
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

    @handle_nonhttp_errors
    def file_metadata(self, bucket_id, file_id):
        """Get file metadata.
        See `API buckets: GET /buckets/{id}/files/{file_id}/info
        <https://storj.github.io/bridge/#!/buckets/get_buckets_id_files_file_id_info>`_
        Args:
            bucket_id (str): bucket unique identifier.
            file_id (str): file unique identifier.
        Returns:
            (:py:class:`storj.model.File`): file metadata.
        """

        self.logger.info('file_metadata(%s, %s)', bucket_id, file_id)

        response = self._request(
            method='GET',
            path='/buckets/%s/files/%s/info' % (bucket_id, file_id))

        if response is not None:
            return model.File(**response)

    @handle_nonhttp_errors
    def file_upload(self, bucket_id, f, frame):
        """Upload file.
        See `API buckets: POST /buckets/{id}/files
        <https://storj.github.io/bridge/#!/buckets/post_buckets_id_files>`_
        Args:
            bucket_id (str): bucket unique identifier.
            f (:py:class:`storj.model.File`): file to be uploaded.
            frame (:py:class:`storj.model.Frame`): frame used to stage file.
        """
        self.logger.info('file_upload(%s, %s, %s)', bucket_id, f, frame)

        def get_size(file_like_object):
            return os.stat(file_like_object.name).st_size

        file_size = get_size(f)

        # TODO:
        # encrypt file
        # shard file

        push_token = self.token_create(bucket_id, 'PUSH')

        self.logger.debug('file_upload() push_token=%s', push_token)

        # upload shards to frame
        # delete encrypted file

        self._request(
            method='POST', path='/buckets/%s/files' % bucket_id,
            # files={'file' : file},
            headers={
                #    'x-token': push_token.id,
                #    'x-filesize': str(file_size)}
                'frame': frame.id,
                'mimetype': f.mimetype,
                'filename': f.filename,
            })

    @handle_nonhttp_errors
    def file_remove(self, bucket_id, file_id):
        """Delete a file pointer from a specified bucket.
        See `API buckets: DELETE /buckets/{id}/files/{file_id}
        <https://storj.github.io/bridge/#!/buckets/delete_buckets_id_files_file_id>`_
        Args:
            bucket_id (str): bucket unique identifier.
            file_id (str): file unique identifier.
        """
        self.logger.info('file_remove(%s, %s)', bucket_id, file_id)

        self._request(
            method='DELETE',
            path='/buckets/%s/files/%s' % (bucket_id, file_id))

    @handle_nonhttp_errors
    def frame_add_shard(self, shard, frame_id, excludes=None):
        """Adds a shard item to the staging frame and negotiates a storage contract.

        See `API frames: PUT /frames/{frame_id}
        <https://storj.github.io/bridge/#!/frames/put_frames_frame_id>`_

        Args:
            shard (:py:class:`storj.models.Shard`): the shard.
            frame_id (str): the frame unique identifier.
        """
        self.logger.info('frame_add_shard(%s, %s)', shard, frame_id)

        data = {
            'hash': shard.hash,
            'size': shard.size,
            'index': shard.index,
            'challenges': shard.challenges,
            'tree': shard.tree.leaves,
            'exclude': excludes,
        }

        response = self._request(
            method='PUT',
            path='/frames/%s' % frame_id,
            json=data)

        return response

    @handle_nonhttp_errors
    def file_mirrors(self, bucket_id, file_id):
        """Get list of established and available mirrors associated with a file.
        Args:
            bucket_id (str): bucket unique identifier.
            file_id (str): file unique identifier.
        Returns:
            (generator[:py:class:`storj.model.FileMirrors`]): list of mirrors of give file.
        """
        # print "test"
        self.logger.info('file_mirrors(%s, %s)', bucket_id, file_id)

        pull_token = self.token_create(bucket_id, operation='PULL')

        response = self._request(
            method='GET',
            path='/buckets/%s/files/%s/mirrors/' % (bucket_id, file_id),
            headers={'x-token': pull_token.id})

        if response is not None:
            for kwargs in response:
                yield model.FileMirrors(**kwargs)
        else:
            raise StopIteration

    @handle_nonhttp_errors
    def frame_create(self):
        """Creates a file staging frame.
        See `API frames: POST /frames
        <https://storj.github.io/bridge/#!/frames/post_frames>`_
        Returns:
            (:py:class:`storj.model.Frame`): the frame.
        """
        self.logger.info('frame_create()')

        response = self._request(
            method='POST',
            path='/frames')

        if response is not None:
            return model.Frame(**response)

    @handle_nonhttp_errors
    def frame_delete(self, frame_id):
        """Destroys the file staging frame by it's unique ID.
        See `API frames: DELETE	/frames/{frame_id}
        <https://storj.github.io/bridge/#!/frames/delete_frames_frame_id>`_
        Args:
            frame_id (str): unique identifier.
        """
        self.logger.info('frame_delete(%s)', frame_id)

        self._request(
            method='DELETE',
            path='/frames/%s' % frame_id,
            json={'frame_id': frame_id})

    @handle_nonhttp_errors
    def frame_get(self, frame_id):
        """Fetches the file staging frame by it's unique ID.
        See `API frame: GET /frames/{frame_id}
        <https://storj.github.io/bridge/#!/frames/get_frames_frame_id>`_
        Args:
            frame_id (str): unique identifier.
        Returns:
            (:py:class:`storj.model.Frame`): a frame.
        """
        self.logger.info('frame_get(%s)', frame_id)

        response = self._request(
            method='GET',
            path='/frames/%s' % frame_id,
            json={'frame_id': frame_id})

        if response is not None:
            return model.Frame(**response)

    @handle_nonhttp_errors
    def frame_list(self):
        """Returns all open file staging frames.
        See `API frame: GET /frames
        < https://storj.github.io/bridge/#!/frames/get_frames>`_
        Returns:
            (generator[:py:class:`storj.model.Frame`]): all open file staging frames.
        """
        self.logger.info('frame_list()')

        response = self._request(
            method='GET',
            path='/frames')

        if response is not None:
            for kwargs in response:
                yield model.Frame(**kwargs)
        else:
            raise StopIteration

    @handle_nonhttp_errors
    def key_delete(self, public_key):
        """Removes a public ECDSA keys.
        See `API keys: DELETE /keys/{pubkey}
        <https://storj.github.io/bridge/#!/keys/delete_keys_pubkey>`_
        Args:
            public_key (str): key to be removed.
        """
        self.logger.info('key_delete(%s)', public_key)
        self._request(
            method='DELETE',
            path='/keys/%s' % public_key)

    def key_dump(self):
        self.logger.info('key_dump()')

        if self.private_key is not None and \
                self.public_key is not None:
            print('Local Private Key: %s\nLocal Public Key: %s' % (self.private_key, self.public_key))

        keys = self.key_list()

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

        self.private_key = SigningKey.generate(curve=SECP256k1, hashfunc=sha256)
        self.public_key = self.private_key.get_verifying_key()

        s = raw_input('Export keys to file for later use? [Y/N]')
        if 'Y' in s.upper():
            self.key_export()

        self.key_register(self.public_key)

    def key_import(self, private_keyfile_path, public_keyfile_path):
        self.logger.info(
            'key_import(%s, %s)',
            private_keyfile_path,
            public_keyfile_path)

        with open(public_keyfile_path, 'r') as f:
            self.public_key = VerifyingKey.from_pem(f.read())

        with open(private_keyfile_path, 'r') as f:
            self.private_key = SigningKey.from_pem(f.read())

        self.key_register(self.public_key)

    @handle_nonhttp_errors
    def key_list(self):
        """Lists the public ECDSA keys associated with the user.
        See `API keys: GET /keys
        <https://storj.github.io/bridge/#!/keys/get_keys>`_
        Returns:
            (list[str]): public keys.
        """
        self.logger.info('key_list()')

        return [kwargs['key'] for kwargs in self._request(
            method='GET',
            path='/keys'
        )]

    @handle_nonhttp_errors
    def key_register(self, public_key):
        """Register an ECDSA public key.
        See `API keys: POST /keys
        <https://storj.github.io/bridge/#!/keys/post_keys>`_
        Returns:
            (list[:py:class:`storj.model.Key`]): public keys.
        """
        self.logger.info('key_register(%s)', public_key)

        self._request(
            method='POST',
            path='/keys',
            json={'key': ecdsa_to_hex(str(public_key))})

    @handle_nonhttp_errors
    def token_create(self, bucket_id, operation):
        """Creates a token for the specified operation.
        See `API buckets: POST /buckets/{id}/tokens
        <https://storj.github.io/bridge/#!/buckets/post_buckets_id_tokens>`_
        Args:
            bucket_id (str): bucket unique identifier.
            operation (str): operation.
        Returns:
            (dict): ...
        """
        self.logger.info('token_create(%s, %s)', bucket_id, operation)

        return model.Token(**self._request(
            method='POST',
            path='/buckets/%s/tokens' % bucket_id,
            json={'operation': operation}))

    @handle_nonhttp_errors
    def send_exchange_report(self, exchange_report_data):
        """Send exchange report to bridge
            Args:
                exchange_report_data (ExchangeReport): exchange report datails.
            Returns:
                (dict): ...
               """
        self.logger.info('send_exchenge_report()')

        data = {
            'dataHash': exchange_report_data.dataHash,
            'reporterId': exchange_report_data.reporterId,
            'farmerId': exchange_report_data.farmerId,
            'clientId': exchange_report_data.clientId,
            'exchangeStart': exchange_report_data.exchangeStart,
            'exchangeEnd': exchange_report_data.exchangeEnd,
            'exchangeResultCode': exchange_report_data.exchangeResultCode,
            'exchangeResultMessage': exchange_report_data.exchangeResultMessage,
        }

        return model.ExchangeReport(**self._request(
            method='POST',
            path='/reports/exchanges',
            json=data))

    @handle_nonhttp_errors
    def user_activate(self, token):
        """Activate user.
        See `API users: GET /activations/{token}
        <https://storj.github.io/bridge/#!/users/get_activations_token>`_
        Args:
            token (str): activation token.
        """
        self.logger.info('user_activate(%s)', token)

        self._request(
            method='GET',
            path='/activations/%s' % token)

    def check_file_existence_in_bucket(self, bucket_id, filepath, file_id=None):
        # checking if file with same name or hash exist in bucket

        with open(filepath, mode='rb') as f:  # b is important -> binary
            fileContent = f.read()
        bname = (os.path.split(filepath))[1]
        file_metadata = self.file_metadata(bucket_id, file_id)
        file_hash = model.ShardManager.hash(fileContent)

        if file_metadata.filename == bname:
            return 1  # same file name
        elif file_metadata.hash == file_hash:
            return 2  # same file RIPEMD160 hash - same file content
        else:
            return False

    @handle_nonhttp_errors
    def user_activation_email(self, email, token):
        """Send user activation email.
        See `API users: POST /activations/{token}
        <https://storj.github.io/bridge/#!/users/post_activations_token>`_
        Args:
            email (str): user's email address.
            token (str): activation token.
       """
        self.logger.info('user_activation_email(%s, %s)', email, token)

        self._request(
            method='GET',
            path='/activations/%s' % token,
            json={
                'email': email,
            })

    @handle_nonhttp_errors
    def user_create(self, email, password):
        """Create a new user with Storj bridge.
        See `API users: POST /users
        <https://storj.github.io/bridge/#!/users/post_users>`_
        Args:
            email (str): user's email address.
            password (str): user's password.
        """
        self.logger.info('user_create(%s, %s)', email, password)

        password = sha256(password).hexdigest()

        response = self._request(
            method='POST',
            path='/users',
            json={
                'email': email,
                'password': password
            })

        return response

    @handle_nonhttp_errors
    def user_deactivate(self, token):
        """Discard activation token.
        See `API users: GET /activations/{token}
        <https://storj.github.io/bridge/#!/users/get_deactivations_token>`_
        Args:
            token (str): activation token.
        """
        self.logger.info('user_deactivate(%s)', token)

        self._request(
            method='DELETE',
            path='/activations/%s' % token)

    @handle_nonhttp_errors
    def user_delete(self, email):
        """Delete user account.
        See `API users: DELETE /users/{email}
        <https://storj.github.io/bridge/#!/users/post_users>`_
        Args:
            email (str): user's email address.
        """
        self.logger.info('user_delete(%s)', email)

        self._request(
            method='DELETE',
            path='/users/%s' % email)

    @handle_nonhttp_errors
    def user_reset_password(self, email):
        """Request a password reset.
        See `API users: PATCH /users/{email}
        <https://storj.github.io/bridge/#!/users/patch_users_email>`_
        Args:
            email (str): user's email address.
        """
        self.logger.info('user_reset_password(%s)', email)

        self._request(
            method='PATCH',
            path='/users/%s' % email)

    @handle_nonhttp_errors
    def user_reset_password_confirmation(self, token):
        """Confirm a password reset request.
        See `API users: GET /resets/{token}
        <https://storj.github.io/bridge/#!/users/get_resets_token>`_
        Args:
            token (str): password reset token.
        """
        self.logger.info('user_reset_password_confirmation(%s)', token)

        self._request(
            method='GET',
            path='/resets/%s' % token)
