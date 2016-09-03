# -*- coding: utf-8 -*-
"""Storj model module."""
import base64
import binascii
import hashlib
import random
import string

from datetime import datetime

from pytz import utc
from steenzout.object import Object
from storj import BucketManager
from storj.sdk import FileManager, BucketKeyManager, TokenManager, hash160, pad


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
        bucket (): bucket unique identifier.
        hash ():
        mimetype ():
        filename ():
        size ():
        shardManager ():
    """

    def __init__(self, bucket=None, hash=None, mimetype=None, filename=None, size=None):
        self.bucket = Bucket(id=bucket)
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
            shard.set_size(shard_size)
            shard.set_hash(hash160(chunk))
            self.addChallenges(shard, chunk)
            shard.set_index(self.index)
            self.index += 1
            self.shards.append(shard)

    def addChallenges(self, shard, shardData, numberOfChallenges=12):
        for i in xrange(numberOfChallenges):
            challenge = self.getRandomChallengeString()

            data2hash = binascii.hexlify('%s%s' % (challenge, shardData))  # concat and hex-encode data

            tree = hash160(hash160(data2hash))  # double hash160 the data

            shard.add_challenge(challenge)
            shard.add_tree(tree)

            def getRandomChallengeString(self):
                    return ''.join(random.choice(string.ascii_letters) for _ in xrange(32))


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

    def add_challenge(self, challenge):
        self.challenges.append(challenge)

    def add_tree(self, tree):
        self.tree.append(tree)


class Keyring:

    def __init__(self):
        self.password = None
        self.salt = None

    def generate(self):
        user_pass = raw_input("Enter your keyring password: ")
        password = hex(random.getrandbits(512*8))[2:-1]
        salt = hex(random.getrandbits(32*8))[2:-1]

        pbkdf2 = hashlib.pbkdf2_hmac('sha512', password, salt, 25000, 512)

        key = hashlib.new('sha256', pbkdf2).hexdigest()
        IV = salt[:16]
        self.export_keyring(password, salt, user_pass)
        self.password = password
        self.salt = salt

    def export_keyring(self, password, salt, user_pass):
        plain = pad("{\"pass\" : \"%s\", \n\"salt\" : \"%s\"\n}" % (password, salt))
        IV = hex(random.getrandbits(8*8))[2:-1]

        aes = AES.new(pad(user_pass), AES.MODE_CBC, IV)

        with open('key.b64', 'wb') as f:
            f.write(base64.b64encode(IV + aes.encrypt(plain)))

    def import_keyring(self, filepath):
        with open(filepath, 'rb') as f:
            keyb64 = f.read()

        user_pass = raw_input('Enter your keyring password: ')

        key_enc = base64.b64decode(keyb64)
        IV = key_enc[:16]
        key = AES.new(pad(user_pass), AES.MODE_CBC, IV)

        # returns the salt and password as a dict
        creds = eval(key.decrypt(key_enc[16:])[:-4])
        self.password = creds['pass']
        self.salt = creds['salt']
        return creds