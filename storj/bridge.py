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

    def call(self, method=None, path=None, headers=None,
             data=None, params=None):
        # TODO doc string

        url = urljoin(self.url, path) if path else self.url
        headers = headers if headers is not None else {}

        if self.privkey:
            pubkey = keys.pubkey_from_privkey(self.privkey)
            headers.update({
                "x-pubkey": pubkey,
                "x-signature": "invalid"  # FIXME create valid signature
            })

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

    def user_reset_password(self):
        """ Requests the reset of the account password.

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

        Args:
            token (str): Deactivation token sent to user's email address.
            redirect (str): TODO correct doc string

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
        return self.call(method='DELETE', path='/keys/'.format(pubkey))

    # ===================== TODO FRAMES =====================

    # ===================== TODO BUCKETS =====================

    # =====================

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

        response = self.call(method='POST', path='/buckets', data=data)
        return model.Bucket(**response)

    def bucket_delete(self, bucket_id):
        """Delete a storage bucket.

        Args:
            bucket_id (string): unique identifier.
        """
        self.logger.info('bucket_delete(%s)', bucket_id)
        self.call(method='DELETE', path='/buckets/%s' % bucket_id)

    def bucket_files(self, bucket_id):
        """

        Args:
            bucket_id (string): unique identifier.
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
            headers={
                'x-token': pull_token['token'],
            })

    def bucket_get(self, bucket_id):
        """Returns buckets.

        Args:
            bucket_id (str): bucket unique identifier.

        Returns:
            (:py:class:`model.Bucket`): bucket.
        """
        try:
            response = self.call(
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

        response = self.call(method='GET', path='/buckets')

        if response is not None:
            for element in response:
                yield model.Bucket(**element)
        else:
            raise StopIteration

    def bucket_set_keys(self, bucket_id, keys):
        self.logger.info('bucket_set_keys()', bucket_id, keys)

        self.call(
            method='PATCH',
            path='/buckets/%s' % bucket_id,
            data={'pubkeys': keys})

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

    def file_get(self, bucket_id):
        self.logger.info('file_get(%s)', bucket_id)

        response = self.call(
            method='GET',
            path='/buckets/%s/files' % bucket_id)

        if response is None:
            return response

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

        # file_size = get_size(file)

        # TODO:
        # encrypt file
        # shard file

        push_token = self.token_create(bucket_id, "PUSH")

        self.logger.debug('upload_file() push_token=%s', push_token)

        # upload shards to frame
        # delete encrypted file

        self.call(
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

        self.call(
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

        response = self.call(
            method='PUT',
            path='/frames/%s' % frame_id,
            data=data)

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

        return self.call(method='POST', path='/frames', data={})

    def frame_delete(self, frame_id):
        """

        Args:
            frame_id (str): unique identifier.
        """
        self.logger.info('frame_delete(%s)', frame_id)

        self.call(
            method='DELETE',
            path='/frames/%s' % frame_id,
            data={'frame_id': frame_id})

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

        response = self.call(
            method='GET',
            path='/frames/%s' % frame_id,
            data={'frame_id': frame_id})

        if response is not None:
            return model.Frame(**response)

    def frame_list(self):
        """Returns all open file staging frames.

        Returns:
            (): all open file staging frames.
        """
        self.logger.info('frame_list()')

        response = self.call(
            method='GET',
            path='/frames',
            data={})

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

        return self.call(
            method='POST',
            path='/buckets/%s/tokens' % bucket_id,
            data={'operation': operation})
