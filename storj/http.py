# -*- coding: utf-8 -*-
"""Storj HTTP module."""

import os
import json
import logging
import requests
from base64 import b64encode
from hashlib import sha256
from io import BytesIO
from micropayment_core import keys
from six.moves.urllib.parse import urljoin
from .web_socket import Client as WSClient
from . import model


class Client(object):

    logger = logging.getLogger('%s.Client' % __name__)

    def __init__(self, email=None, password=None, privkey=None,
                 url="https://api.storj.io/"):
        self.url = url
        self.session = requests.Session()
        self.privkey = privkey
        self.email = email
        self.password = sha256(password.encode('ascii')).hexdigest()

    def _get_signature(self, method, path, data, params):
        if method in ['POST', 'PATCH', 'PUT']:
            payload = json.dumps(data)
        elif method in ['GET', 'DELETE', 'OPTIONS']:
            payload = "&".join(["=".join(i) for i in params.items()])
        else:
            raise Exception("Invalid method: {0}".format(method))
        sigmessage = "\n".join([method, path, payload])
        return keys.sign_sha256(self.privkey, sigmessage)

    def call(self, method=None, path=None, headers=None,
             data=None, params=None):
        # TODO doc string
        path = path or ""
        headers = headers if headers is not None else {}
        params = params or {}
        url = urljoin(self.url, path)

        if self.privkey:
            pubkey = keys.pubkey_from_privkey(self.privkey)
            signature = self._get_signature(method, path, data, params)
            headers.update({"x-pubkey": pubkey, "x-signature": signature})

        # basic auth
        elif self.email and self.password:
            # TODO use requests.auth.HTTPBasicAuth instead?
            headers.update({
                'Authorization': b'Basic ' + b64encode(
                    ('%s:%s' % (self.email, self.password)).encode('ascii')
                )
            })

        else:
            raise Exception("No auth credentials!")

        kwargs = dict(
            method=method, url=url, headers=headers,
            data=json.dumps(data), params=params,
        )
        # print("REQUEST:", json.dumps(kwargs, indent=2))
        response = self.session.send(requests.Request(**kwargs).prepare())
        response.raise_for_status()
        result = response.json()
        # print("RESPONSE:", result)

        return result

    def contacts_list(self, **kwargs):
        """ Lists the contacts according to the supplied query.

        Args:
            page (str): Paginagtion indicator, defaults to 1.
            address (str): Hostname or IP address.
            protocol (str): SemVer protocol tag.
            userAgent (str): Storj user agent string for farming client.
            connected (str): Filter results by connection status (true/false)

        Returns:
            [
                {
                    "address": "api.storj.io",
                    "port": 8443,
                    "userAgent": "userAgent",
                    "nodeID": "32033d2dc11b877df4b1caefbffba06495ae6b18",
                    "lastSeen": "2016-05-24T15:16:01.139Z",
                    "protocol": "0.7.0"
                }
            ]

        See:
            https://storj.github.io/bridge/#!/contacts/get_contacts
        """
        return self.call(method='GET', path='/contacts', params=kwargs)

    def contact_information(self, nodeid):
        """ Performs a lookup for the contact information of a node.

        Args:
            nodeid (str): Node ID of the contact to lookup.

        Returns:
            {
                "address": "api.storj.io",
                "port": 8443,
                "nodeID": "32033d2dc11b877df4b1caefbffba06495ae6b18",
                "lastSeen": "2016-05-24T15:16:01.139Z",
                "protocol": "0.7.0"
            }

        See:
            https://storj.github.io/bridge/#!/contacts/get_contacts_nodeID
        """
        return self.call(method='GET', path='/contacts/{0}'.format(nodeid))

    def user_register(self):
        """ Registers a new user account with Storj Bridge.

        Returns:
            {
                "email": "gordon@storj.io",
                "created": "2016-03-04T17:01:02.629Z",
                "activated": true
            }

        See:
            https://storj.github.io/bridge/#!/users/post_users
        """
        privkey = self.privkey
        pubkey = keys.pubkey_from_privkey(privkey) if privkey else None
        return self.call(
            method='POST',
            path='/users',
            data={
                "email": self.email,
                "password": self.password,
                "pubkey": pubkey
            }
        )

    def user_delete(self, redirect=None):
        """ Requests the deletion of the account.

        Args:
            redirect (str): Optional redirect URL for successful deletion.

        Returns:
            {
                "email": "gordon@storj.io",
                "created": "2016-03-04T17:01:02.629Z",
                "activated": true
            }

        See:
            https://storj.github.io/bridge/#!/users/delete_users_email
        """
        return self.call(
            method='DELETE',
            path='/users/{0}'.format(self.email),
            data={"redirect": redirect} if redirect else {}
        )

<<<<<<< HEAD
    def _prepare_request(self, **kwargs):
        """Prepares a HTTP request.

        Args:
            kwargs (dict): keyword arguments for the authentication function
                (``_add_ecdsa_signature()`` or ``_add_basic_auth()``) and
                :py:class:`requests.Request` class.

        Raises:
            AssertionError: in case ``kwargs['path']`` doesn't start with ``/``.
        """
=======
    def user_reset_password(self):
        """ Requests the reset of the account password.
>>>>>>> 337f217addbabf4152983ad53190379abc5061ba

        Returns:
            {
                "email": "gordon@storj.io",
                "created": "2016-03-04T17:01:02.629Z",
                "activated": true
            }

        See:
            https://storj.github.io/bridge/#!/users/patch_users_email
        """
        return self.call(
            method='PATCH',
            path='/users/{0}'.format(self.email),
        )

    def user_confirm_reset(self, token, redirect=None):
        """ Confirms the password reset and optionally redirects.

        Args:
            token (str): Confirmation token sent to user's email address.
            redirect (str): Optional redirect URL for successful confirmation.

        Returns:
            {
                "email": "gordon@storj.io",
                "created": "2016-03-04T17:01:02.629Z",
                "activated": true
            }

        See:
            https://storj.github.io/bridge/#!/users/get_resets_token
        """
        return self.call(
            method='GET',
            path='/resets/{0}'.format(token),
            params={"redirect": redirect} if redirect is not None else {}
        )

    def user_activate(self, token, redirect=None):
        """ Activates a registered user and optionally redirects.

        Args:
            token (str): Activation token sent to user's email address.
            redirect (str): Optional redirect URL for successful confirmation.

        Returns:
            {
                "email": "gordon@storj.io",
                "created": "2016-03-04T17:01:02.629Z",
                "activated": true
            }

        See:
            https://storj.github.io/bridge/#!/users/get_activations_token
        """
        return self.call(
            method='GET',
            path='/activations/{0}'.format(token),
            params={"redirect": redirect} if redirect is not None else {}
        )

    def user_reactivate(self, token, redirect):
        """ Sends the user email for reactivating a disabled account.

<<<<<<< HEAD
        try:
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            self.logger.error(e)
            self.logger.debug('response.text=%s', response.text)
            raise StorjBridgeApiError(response.text)
=======
        Args:
            token (str): Deactivation token sent to user's email address.
            redirect (str): TODO correct doc string
>>>>>>> 337f217addbabf4152983ad53190379abc5061ba

        Returns:
            {
                "email": "gordon@storj.io",
                "created": "2016-03-04T17:01:02.629Z",
                "activated": true
            }

        See:
            https://storj.github.io/bridge/#!/users/post_activations_token
        """
        return self.call(
            method='POST',
            path='/activations/{0}'.format(token),
            data={"redirect": redirect, "email": self.email}
        )

    def user_deactivate(self, token, redirect=None):
        """ Deactivates a registered user and optionally redirects

        Args:
            token (str): Deactivation token sent to user's email address.
            redirect (str): Optional redirect URL for successful deactivation.

        Returns:
            {
                "email": "gordon@storj.io",
                "created": "2016-03-04T17:01:02.629Z",
                "activated": true
            }

        See:
            https://storj.github.io/bridge/#!/users/get_deactivations_token
        """
        return self.call(
            method='GET',
            path='/deactivations/{0}'.format(token),
            params={"redirect": redirect} if redirect is not None else {}
        )

    def keys_list(self):
        """ Lists the public ECDSA keys associated with the user.

        Returns:
            [
                {
                    "key": "pubkey",
                    "user": "gordon@storj.io"
                }
            ]

        See:
            https://storj.github.io/bridge/#!/keys/get_keys
        """
        return self.call(method='GET', path='/keys')

    def keys_register(self, pubkey):
        """ Registers an ECDSA public key for the user account.

        Args:
            pubkey (str): Hex encoded 33Byte compressed public key.

        Returns:
            {
                "key": "pubkey",
                "user": "gordon@storj.io"
            }

        See:
            https://storj.github.io/bridge/#!/keys/post_keys
        """
        # FIXME nothing signed, should prove control of private key
        return self.call(method='POST', path='/keys', data={'key': pubkey})

    def keys_delete(self, pubkey):
        """ Destroys a ECDSA public key for the user account.

        Args:
            pubkey (str): Hex encoded 33Byte compressed public key.

        See:
            https://storj.github.io/bridge/#!/keys/delete_keys_pubkey
        """
        return self.call(method='DELETE', path='/keys/{0}'.format(pubkey))

    # ===================== TODO FRAMES =====================

    # ===================== TODO BUCKETS =====================

    # =====================

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

<<<<<<< HEAD
        return model.Bucket(**self._request(method='POST', path='/buckets', json=data))
=======
        response = self.call(method='POST', path='/buckets', data=data)
        return model.Bucket(**response)
>>>>>>> 337f217addbabf4152983ad53190379abc5061ba

    def bucket_delete(self, bucket_id):
        """Destroy a storage bucket.

        See `API buckets: DELETE /buckets/{id}
        <https://storj.github.io/bridge/#!/buckets/delete_buckets_id>`_

        Args:
            bucket_id (string): unique identifier.
        """
        self.logger.info('bucket_delete(%s)', bucket_id)
        self.call(method='DELETE', path='/buckets/%s' % bucket_id)

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

        pull_token = self.token_create(bucket_id, operation='PULL')
        return self.call(
            method='GET',
            path='/buckets/%s/files/' % (bucket_id),
            headers={
                'x-token': pull_token['token'],
            })

    def file_pointers(self, bucket_id, file_id):
        """

        Args:
            bucket_id (string): unique identifier.
        """
        self.logger.info('bucket_files(%s, %s)', bucket_id, file_id)

        pull_token = self.token_create(bucket_id, operation='PULL')
        return self.call(
            method='GET',
            path='/buckets/%s/files/%s/' % (bucket_id, file_id),
            headers={  # FIXME undocumented unsigned header!!!
                'x-token': pull_token['token'],
            }
        )

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
<<<<<<< HEAD
            return model.Bucket(**self._request(
=======
            response = self.call(
>>>>>>> 337f217addbabf4152983ad53190379abc5061ba
                method='GET',
                path='/buckets/%s' % bucket_id))

        except requests.HTTPError as e:
            if e.response.status_code == requests.codes.not_found:
                return None
            else:
                self.logger.error('bucket_get() error=%s', e)
                raise StorjBridgeApiError()

    def bucket_list(self):
        """List all of the buckets belonging to the user.

        See `API buckets: GET /buckets
        <https://storj.github.io/bridge/#!/buckets/get_buckets>`_

        Returns:
            (generator[:py:class:`model.Bucket`]): buckets.
        """
        self.logger.info('bucket_list()')

        response = self.call(method='GET', path='/buckets')

        if response is not None:
            for element in response:
                yield model.Bucket(**element)
        else:
            raise StopIteration

    def bucket_set_keys(self, bucket_id, bucket_name, keys):
        """Update the bucket with the given public keys.

<<<<<<< HEAD
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

    def file_pointers(self, bucket_id, file_id, skip=None, limit=None):
        """Get list of pointers associated with a file.

        See `API buckets: GET /buckets/{id}/files/{file_id}
        <https://storj.github.io/bridge/#!/buckets/get_buckets_id_files_file_id>`_

        Args:
            bucket_id (str): bucket unique identifier.
            file_id (str): file unique identifier.
            skip (str): pointer index to start the file slice.
            limit (str): number of pointers to resolve tokens for.

        Returns:
            (generator[:py:class:`storj.model.FilePointer`]): file pointers.
        """
        self.logger.info('bucket_files(%s, %s)', bucket_id, file_id)

        pull_token = self.token_create(bucket_id, operation='PULL')

        response = self._request(
            method='GET',
            path='/buckets/%s/files/%s/' % (bucket_id, file_id),
            headers={'x-token': pull_token.id})

        if response is not None:
            for kwargs in response:
                yield model.FilePointer(**kwargs)
        else:
            raise StopIteration
=======
        self.call(
            method='PATCH',
            path='/buckets/%s' % bucket_id,
            data={'pubkeys': keys})
>>>>>>> 337f217addbabf4152983ad53190379abc5061ba

    def file_download(self, bucket_id, file_id):
        self.logger.info('file_pointers(%s, %s)', bucket_id, file_id)

        pointers = self.file_pointers(
            bucket_id=bucket_id, file_id=file_id)

        file_contents = BytesIO()
        for pointer in pointers:
            ws = WSClient(pointer=pointer, file_contents=file_contents)
            ws.connect()
            ws.run_forever()

        return file_contents

<<<<<<< HEAD
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

        self.logger.info('file_metadata(%s, %s, %s)', bucket_id, file_id)

        response = self._request(
            method='GET',
            path='/buckets/%s/files/%s/info' % (bucket_id, file_id))

        if response is not None:
            return model.File(**response)
=======
    def file_get(self, bucket_id):
        self.logger.info('file_get(%s)', bucket_id)

        response = self.call(
            method='GET',
            path='/buckets/%s/files' % bucket_id)

        if response is None:
            return response
>>>>>>> 337f217addbabf4152983ad53190379abc5061ba

    def file_upload(self, bucket_id, file, frame):
        """Upload file.

        See `API buckets: POST /buckets/{id}/files
        <https://storj.github.io/bridge/#!/buckets/post_buckets_id_files>`_

        Args:
            bucket_id (str): bucket unique identifier.
            file (:py:class:`storj.model.File`): file to be uploaded.
            frame (:py:class:`storj.model.Frame`): frame used to stage file.
        """
        self.logger.info('file_upload(%s, %s, %s)', bucket_id, file, frame)

        def get_size(file_like_object):
            return os.stat(file_like_object.name).st_size

        # file_size = get_size(file)

        # TODO:
        # encrypt file
        # shard file

        push_token = self.token_create(bucket_id, 'PUSH')

        self.logger.debug('file_upload() push_token=%s', push_token)

        # upload shards to frame
        # delete encrypted file

        self.call(
            method='POST', path='/buckets/%s/files' % bucket_id,
            # files={'file' : file},
            headers={
                #    'x-token': push_token.id,
                #    'x-filesize': str(file_size)}
                'frame': frame.id,
                'mimetype': file.mimetype,
                'filename': file.filename,
            })

    def file_remove(self, bucket_id, file_id):
        """Delete a file pointer from a specified bucket.

        See `API buckets: DELETE /buckets/{id}/files/{file_id}
        <https://storj.github.io/bridge/#!/buckets/delete_buckets_id_files_file_id>`_

        Args:
            bucket_id (str): bucket unique identifier.
            file_id (str): file unique identifier.
        """
        self.logger.info('file_remove(%s, %s)', bucket_id, file_id)

        self.call(
            method='DELETE',
            path='/buckets/%s/files/%s' % (bucket_id, file_id))

    def frame_add_shard(self, shard, frame_id):
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
            'tree': shard.tree,
        }

        response = self.call(
            method='PUT',
            path='/frames/%s' % frame_id,
            data=data)

        if response is not None:
            return response

    def frame_create(self):
        """Creates a file staging frame.

        See `API frames: POST /frames
        <https://storj.github.io/bridge/#!/frames/post_frames>`_

        Returns:
            (:py:class:`storj.model.Frame`): the frame.
        """
        self.logger.info('frame_create()')

<<<<<<< HEAD
        response = self._request(
            method='POST',
            path='/frames')

        if response is not None:
            return model.Frame(**response)
=======
        return self.call(method='POST', path='/frames', data={})
>>>>>>> 337f217addbabf4152983ad53190379abc5061ba

    def frame_delete(self, frame_id):
        """Destroys the file staging frame by it's unique ID.

        See `API frames: DELETE	/frames/{frame_id}
        <https://storj.github.io/bridge/#!/frames/delete_frames_frame_id>`_

        Args:
            frame_id (str): unique identifier.
        """
        self.logger.info('frame_delete(%s)', frame_id)

        self.call(
            method='DELETE',
            path='/frames/%s' % frame_id,
            data={'frame_id': frame_id})

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

        response = self.call(
            method='GET',
            path='/frames/%s' % frame_id,
            data={'frame_id': frame_id})

        if response is not None:
            return model.Frame(**response)

    def frame_list(self):
        """Returns all open file staging frames.

        See `API frame: GET /frames
        < https://storj.github.io/bridge/#!/frames/get_frames>`_

        Returns:
            (generator[:py:class:`storj.model.Frame`]): all open file staging frames.
        """
        self.logger.info('frame_list()')

        response = self.call(
            method='GET',
<<<<<<< HEAD
            path='/frames')

        if response is not None:
            for kwargs in response:
                yield model.Frame(**kwargs)
        else:
            raise StopIteration

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
            print('Local Private Key: %s' % self.private_key
                  + '\nLocal Public Key: %s' % self.public_key)

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
        (self.private_key, self.public_key) = storj.generate_new_key_pair()

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
            json={'key': ecdsa_to_hex(public_key)})
=======
            path='/frames',
            data={})
>>>>>>> 337f217addbabf4152983ad53190379abc5061ba

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

<<<<<<< HEAD
        return model.Token(**self._request(
            method='POST',
            path='/buckets/%s/tokens' % bucket_id,
            json={'operation': operation}))

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

        self._request(
            method='POST',
            path='/users',
            json={
                'email': email,
                'password': password
            })

        self.authenticate(email=email, password=password)

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
=======
        return self.call(
            method='POST',
            path='/buckets/%s/tokens' % bucket_id,
            data={'operation': operation})
>>>>>>> 337f217addbabf4152983ad53190379abc5061ba
