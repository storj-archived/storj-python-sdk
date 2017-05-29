# -*- coding: utf-8 -*-
"""Storj model module."""

import base58
import base64
import binascii
import hashlib
import logging
import math
import io
import random
import os

import six
import strict_rfc3339
import types

from Crypto.Cipher import AES
from datetime import datetime

from micropayment_core import keys

from os import urandom

from pycoin.key.Key import Key
from pycoin.serialize import b2h
from pycoin.key.BIP32Node import BIP32Node
from pycoin.serialize.bitcoin_streamer import stream_bc_string
from pycoin.ecdsa import numbertheory, generator_secp256k1
from pycoin.encoding import to_bytes_32, from_bytes_32, double_sha256

from steenzout.object import Object

from sys import platform


class Bucket(Object):
    """Storage bucket.
    A bucket is a logical grouping of files
    which the user can assign permissions and limits to.
    Attributes:
        id (str): unique identifier.
        name (str): name.
        status (str): bucket status (Active, ...).
        user (str): user email address.
        created (:py:class:`datetime.datetime`): time when the bucket was created.
        storage (int): storage limit (in GB).
        transfer (int): transfer limit (in GB).
        pubkeys ():
    """

    def __init__(
        self, id=None, name=None, status=None, user=None,
        created=None, storage=None, transfer=None, pubkeys=None,
        publicPermissions=None, encryptionKey=None, index=None
    ):
        self.id = id
        self.name = name
        self.status = status
        self.user = user
        self.storage = storage
        self.transfer = transfer
        self.pubkeys = pubkeys
        self.publicPermissions = publicPermissions
        self.encryptionKey = encryptionKey
        self.index = index

        # self.files = FileManager(bucket_id=self.id)
        # self.pubkeys = BucketKeyManager(
        #     bucket=self, authorized_public_keys=self.pubkeys)
        # self.tokens = TokenManager(bucket_id=self.id)

        if created is not None:
            self.created = datetime.fromtimestamp(
                strict_rfc3339.rfc3339_to_timestamp(created))
        else:
            self.created = None


class Contact(Object):
    """Contact.
    Attributes:
        address (str): hostname or IP address.
        port (str): .
        nodeID (str): node unique identifier.
        lastSeen (str): .
        protocol (str): SemVer protocol tag.
        userAgent (str):
    """

    def __init__(
        self, address=None, port=None, nodeID=None,
        lastSeen=None, protocol=None, userAgent=None, responseTime=None, timeoutRate=None, lastTimeout=None
    ):
        self.address = address
        self.port = port
        self.nodeID = nodeID
        self.lastSeen = lastSeen
        self.protocol = protocol
        self.userAgent = userAgent
        self.responseTime = responseTime
        self.timeoutRate = timeoutRate
        self.lastTimeout = lastTimeout

    @property
    def lastSeen(self):
        return self._last_seen

    @lastSeen.setter
    def lastSeen(self, value):

        if value is not None:
            self._last_seen = datetime.fromtimestamp(
                strict_rfc3339.rfc3339_to_timestamp(value))
        else:
            self._last_seen = None


class File(Object):
    """
    Attributes:
        bucket (): bucket unique identifier.
        hash ():
        mimetype ():
        filename ():
        frame (:py:class:`storj.model.Frame`): file frame.
        size ():
        shard_manager ():
    """

    def __init__(self, bucket=None, hash=None, mimetype=None,
                 filename=None, size=None, id=None, frame=None, created=None, hmac=None, erasure=None, index=None):
        self.bucket = Bucket(id=bucket)
        self.hash = hash
        self.mimetype = mimetype
        self.filename = filename
        self.size = size
        self.erasure = erasure
        self.index = index
        self.shard_manager = None
        self.id = id
        self.frame = Frame(id=frame)
        self.created = created
        self.hmac = hmac

    @property
    def content_type(self):
        return self.mimetype

    @property
    def name(self):
        return self.filename


class FilePointer(Object):
    """File pointer.
    Args:
        hash (str):
        token (str): token unique identifier.
        operation (str):
        channel (str):
    Attributes:
        hash (str):
        token (:py:class:`storj.model.Token`): token.
        operation (str):
        channel (str):
    """

    def __init__(self, hash=None, token=None, operation=None, channel=None):
        self.hash = hash
        self.token = Token(id=token)
        self.operation = operation
        self.channel = channel


class Frame(Object):
    """File staging frame.
    Attributes:
        id (str): unique identifier.
        created (:py:class:`datetime.datetime`):
            time when the bucket was created.
        shards (list[:py:class:`Shard`]): shards that compose this frame.
    """

    def __init__(self, id=None, created=None, shards=None, locked=None, user=None, size=None, storageSize=None):
        self.id = id
        self.locked = locked
        self.user = user
        self.size = size
        self.storageSize = storageSize

        if created is not None:
            self.created = datetime.fromtimestamp(
                strict_rfc3339.rfc3339_to_timestamp(created))
        else:
            self.created = None

        if shards is None:
            self.shards = []
        else:
            self.shards = shards


class KeyPair(object):
    """
    ECDSA key pair.
    Args:
        pkey (str): hexadecimal representation of the private key (secret exponent).
        secret (str): master password.
    Attributes:
        keypair (:py:class:`pycoin.key.Key.Key`): BIP0032-style hierarchical wallet.
    Raises:
        NotImplementedError when
            a randomness source is not found.
    """

    def __init__(self, pkey=None, secret=None):

        if secret is not None:
            pkey = format(
                BIP32Node.from_master_secret(
                    secret.encode('utf-8')
                ).secret_exponent(), "064x")

        elif pkey is None:
            try:
                pkey = format(
                    BIP32Node.from_master_secret(
                        urandom(4096)
                    ).secret_exponent(), '064x')
            except NotImplementedError as e:
                raise ValueError('No randomness source found: %s' % e)

        self.keypair = Key(secret_exponent=int(pkey, 16))

    @property
    def node_id(self):
        """(str): NodeID derived from the public key (RIPEMD160 hash of public key)."""
        return b2h(self.keypair.hash160())

    @property
    def public_key(self):
        """(str): public key."""
        return b2h(self.keypair.sec(use_uncompressed=False))

    @property
    def private_key(self):
        """(str): private key."""
        return format(self.keypair.secret_exponent(), '064x')

    @property
    def address(self):
        """(): base58 encoded bitcoin address version of the nodeID."""
        return self.keypair.address(use_uncompressed=False)

    def sign(self, message, compact=True):
        """Signs the supplied message with the private key"""
        if compact:
            fd = io.BytesIO()
            stream_bc_string(fd, bytearray('Bitcoin Signed Message:\n', 'ascii'))
            stream_bc_string(fd, bytearray(message, 'utf-8'))
            mhash = from_bytes_32(double_sha256(fd.getvalue()))

            G = generator_secp256k1
            n = G.order()

            k = from_bytes_32(os.urandom(32))
            p1 = k * G
            r = p1.x()
            if r == 0:
                raise RuntimeError("amazingly unlucky random number r")
            s = (numbertheory.inverse_mod(k, n) *
                 (mhash + (self.keypair.secret_exponent() * r) % n)) % n
            if s == 0:
                raise RuntimeError("amazingly unlucky random number s")

            y_odd = p1.y() % 2
            assert y_odd in (0, 1)

            first = 27 + y_odd + (4 if not self.keypair._use_uncompressed(False) else 0)
            sig = binascii.b2a_base64(bytearray([first]) + to_bytes_32(r) + to_bytes_32(s)).strip()

            if not isinstance(sig, str):
                # python3 b2a wrongness
                sig = str(sig, 'ascii')

            return sig
        else:
            return keys.sign_sha256(self.private_key, message)


class IdecdsaCipher(Object):
    """Tools for en-/decrypt private key to/from id_ecdsa"""

    @staticmethod
    def pad(data):
        """input data is returned as a padded multiple of 16 bytes"""
        padding = 16 - len(data) % 16
        return '%s%s' % (data, padding * chr(padding))

    @staticmethod
    def unpad(data):
        """removes padding from input data and returns unpadded data"""
        return data[0:-ord(data[-1])]

    def decrypt(self, data, key, iv):
        """Decrypt data.
        The steps are:
        1. decrypt the data
        2. remove padding
        3. decode result from hexadecimal format
        Args:
            data (str/bytes): encrypted data.
            key (str):
            iv (str):
        Returns:
            (str): original data.
        """
        aes = AES.new(key, AES.MODE_CBC, iv)
        return self.unpad(aes.decrypt(data)).decode('hex')

    def encrypt(self, data, key, iv):
        """Encrypt data.
        The steps are:
        1. encode data to hexadecimal format
        2. add padding
        3. encrypt the result
        Args:
            data (str/bytes): original data.
            key (str):
            iv (str):
        Returns:
            (str): encrypted data
        """
        aes = AES.new(key, AES.MODE_CBC, iv)
        return aes.encrypt(self.pad(data.encode('hex')))

    def EVP_BytesToKey(self, password, key_len, iv_len):
        """derives a key and IV from various parameters"""
        # equivalent to OpenSSL's EVP_BytesToKey() with count 1
        # so that we make the same key and iv as nodejs version
        m = []
        len_m = 0
        i = 0
        utf8_password = password.encode('utf-8')  # in python3 this is bytes
        while len_m < (key_len + iv_len):
            md5 = hashlib.md5()
            data = utf8_password
            if i > 0:
                data = m[i - 1] + utf8_password
            md5.update(data)
            md5_digest = md5.digest()
            m.append(md5_digest)
            len_m += len(md5_digest)
            i += 1

        ms = ''.encode('utf-8')
        for mi in m:
            ms += mi

        key = ms[:key_len]
        iv = ms[key_len:key_len + iv_len]

        return key, iv

    def simpleEncrypt(self, passphrase, data):
        """Encrypt data.
        Args:
            passphrase (str): passphrase to use for encryption.
            data (str/bytes): original data.
        Returns:
            (str): base58-encoded encrypted data.
        """
        key, iv = self.EVP_BytesToKey(passphrase, 32, 16)
        return base58.b58encode(self.encrypt(data, key, iv))

    def simpleDecrypt(self, passphrase, base58_data):
        """Decrypt data.
        Args:
            passphrase (str): passphrase to use for decryption.
            base58_data (str/bytes): base58-encoded encrypted data.
        Returns:
            (str): original data.
        """
        key, iv = self.EVP_BytesToKey(passphrase, 32, 16)
        return self.decrypt(base58.b58decode(base58_data), key, iv)


class Keyring(Object):
    def __init__(self):
        self.password = None
        self.salt = None

    def generate(self):
        user_pass = raw_input("Enter your keyring password: ")
        password = hex(random.getrandbits(512 * 8))[2:-1]
        salt = hex(random.getrandbits(32 * 8))[2:-1]

        pbkdf2 = hashlib.pbkdf2_hmac('sha512', password, salt, 25000, 512)

        key = hashlib.new('sha256', pbkdf2).hexdigest()
        IV = salt[:16]
        self.export_keyring(password, salt, user_pass)
        self.password = password
        self.salt = salt

    def get_encryption_key(self, user_pass):
        # user_pass = raw_input("Enter your keyring password: ")
        password = hex(random.getrandbits(512 * 8))[2:-1]
        salt = hex(random.getrandbits(32 * 8))[2:-1]

        pbkdf2 = hashlib.pbkdf2_hmac('sha512', password, salt, 25000, 512)

        key = hashlib.new('sha256', pbkdf2).hexdigest()
        IV = salt[:16]
        # self.export_keyring(password, salt, user_pass)
        self.password = password
        self.salt = salt

        return key

    def export_keyring(self, password, salt, user_pass):
        plain = self.pad('{"pass" : "%s", \n"salt" : "%s"\n}' % (password, salt))
        IV = hex(random.getrandbits(8 * 8))[2:-1]

        aes = AES.new(self.pad(user_pass), AES.MODE_CBC, IV)

        with open('key.b64', 'wb') as f:
            f.write(base64.b64encode(IV + aes.encrypt(plain)))

    def import_keyring(self, filepath):
        with open(filepath, 'rb') as f:
            keyb64 = f.read()

        user_pass = raw_input('Enter your keyring password: ')

        key_enc = base64.b64decode(keyb64)
        IV = key_enc[:16]
        key = AES.new(self.pad(user_pass), AES.MODE_CBC, IV)

        # returns the salt and password as a dict
        creds = eval(key.decrypt(key_enc[16:])[:-4])
        self.password = creds['pass']
        self.salt = creds['salt']
        return creds


class MerkleTree(Object):
    """Simple merkle hash tree.
    Nodes are stored as strings in rows.
    Row 0 is the root node, row 1 is its children, row 2 is their children, etc
    Args:
        leaves (list[str]/types.generator[str]):
            leaves of the tree, as hex digests
    Attributes:
        leaves (list[str]): leaves of the tree, as hex digests
        depth (int): the number of levels in the tree
        count (int): the number of nodes in the tree
        rows (list[list[str]]): the levels of the tree
    """

    def __init__(self, leaves, prehashed=True):

        self.prehashed = prehashed
        self.leaves = leaves
        self.count = 0
        self._rows = []

        self._generate()

    @property
    def depth(self):
        """Calculates the depth of the tree.
        Returns:
            (int): tree depth.
        """
        pow = 0

        while (2 ** pow) < len(self._leaves):
            pow += 1

        return pow

    @property
    def leaves(self):
        """(list[str]/types.generator[str]): leaves of the tree."""
        return self._leaves

    @leaves.setter
    def leaves(self, value):

        if value is None:
            raise ValueError('Leaves should be a list.')
        elif not isinstance(value, list) and \
                not isinstance(value, types.GeneratorType):
            raise ValueError('Leaves should be a list or a generator (%s).' % type(value))

        if self.prehashed:
            # it will create a copy of list or
            # it will create a new list based on the generator
            self._leaves = list(value)
        else:
            self._leaves = [ShardManager.hash(leaf) for leaf in value]

        if not len(self._leaves) > 0:
            raise ValueError('Leaves must contain at least one entry.')

        for leaf in self._leaves:
            if not isinstance(leaf, six.string_types):
                raise ValueError('Leaves should only contain strings.')

    def _generate(self):
        """Generate the merkle tree from the leaves"""
        self._rows = [[] for _ in range(self.depth + 1)]

        # The number of leaves should be filled with hash of empty strings
        # until the number of leaves is a power of 2.
        # See https://storj.github.io/core/tutorial-protocol-spec.html
        while len(self._leaves) < (2 ** self.depth):
            self._leaves.append(ShardManager.hash(''))

        leaf_row = self.depth
        next_branches = self.depth - 1

        self._rows[leaf_row] = self._leaves
        if not self.prehashed:
            self.count += len(self._leaves)

        # Generate each row, starting from the bottom

        while next_branches >= 0:
            self._rows[next_branches] = self._make_row(next_branches)
            self.count += len(self._rows[next_branches])
            next_branches -= 1

    def _make_row(self, depth):
        """Generate the row at the specified depth"""
        row = []

        prior = self._rows[depth + 1]

        for i in range(0, len(prior), 2):
            entry = ShardManager.hash('%s%s' % (prior[i], prior[i + 1]))
            row.append(entry)

        return row

    def get_root(self):
        """Return the root of the tree"""
        return self._rows[0][0]

    def get_level(self, depth):
        """Returns the tree row at the specified depth"""
        return self._rows[depth]


class Mirror(Object):
    """Mirror or file replica settings.
    Attributes:
        hash (str):
        mirrors (int): number of file replicas.
        status (str): current file replica status.
    """

    def __init__(self, hash=None, mirrors=None, status=None):
        self.hash = hash
        self.mirrors = mirrors
        self.status = status


class FileMirrors(Object):
    """File mirrors
    Attributes:
        available (str): list of available mirrors
        established (str): list of established
    """

    def __init__(self, available=None, established=None):
        self.established = established
        self.available = available


class Shard(Object):
    """Shard.
    Attributes:
        id (str): unique identifier.
        hash (str): hash of the data.
        size (long): size of the shard in bytes.
        index (int): numeric index of the shard in the frame.
        challenges (list[str]): list of challenge numbers
        tree (list[str]): audit merkle tree.
        exclude (list[str]): list of farmer nodeIDs to exclude
    """

    def __init__(self, id=None, hash=None, size=None, index=None,
                 challenges=None, tree=None, exclude=None):
        self.id = id
        self.hash = hash
        self.size = size
        self.index = index
        self.challenges = challenges
        self.tree = tree
        self.exclude = exclude

        if challenges is not None:
            self.challenges = challenges
        else:
            self.challenges = []

        if tree is not None:
            self.tree = tree
        else:
            self.tree = []

        if exclude is not None:
            self.exclude = exclude
        else:
            self.exclude = []

    def all(self):
        return_string = 'Shard{index=%s, hash=%s, ' % (
            self.index,
            self.hash)
        return_string += 'size=%s, tree={%s}, challenges={%s}' % (
            self.size,
            ', '.join(self.tree),
            ', '.join(self.challenges))
        return return_string

    def add_challenge(self, challenge):
        """Append challenge.
        Args:
            challenge (str):.
        """
        self.challenges.append(challenge)

    def add_tree(self, tree):
        """Append tree."""
        self.tree.append(tree)

    def get_public_record(self):
        pass

    def get_private_record(self):
        pass


class ShardingException(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return str(self.value)


class ShardManager(Object):
    """
    Attributes:
        tmp_path (str): directory where the chunk files will reside.
        nchallenges : number of challenges.
        shards (list[]): shards.
        filepath (str): path to the original file.
        num_chunks (int): number of chunks used to split the file.
        suffix (str): suffix to be used on chunk file names.
    """

    __logger = logging.getLogger('%s.ShardManager' % __name__)

    MAX_SHARD_SIZE = 4294967296  # 4Gb
    SHARD_MULTIPLES_BACK = 4
    SHARD_SIZE = 8 * (1024 * 1024)  # 8Mb

    def __init__(self, filepath, num_chunks=0, tmp_path=None, nchallenges=2, suffix=''):
        self.num_chunks = num_chunks
        self.nchallenges = nchallenges
        self.shards = []
        self.suffix = suffix
        self.tmp_path = tmp_path

        # IMPORTANT: set filepath last
        self.filepath = filepath

    @property
    def filepath(self):
        """(str): path to the file."""
        return self._filepath

    @filepath.setter
    def filepath(self, value):
        if not isinstance(value, six.string_types):
            raise ValueError('%s must be a string' % value)
        elif not os.path.exists(value):
            raise ValueError('%s must exist' % value)
        elif not os.path.isfile(value):
            raise ValueError('%s must be a file' % value)

        self._filepath = value
        self._filesize = os.path.getsize(value)
        self._make_shards()

    @property
    def filesize(self):
        """(long): file size."""
        return self._filesize

    @property
    def tmp_path(self):
        """(str): path to the temporary directory."""
        return self._tmp_path

    @tmp_path.setter
    def tmp_path(self, value):

        if value is not None:
            self._tmp_path = value

        elif platform == 'linux' or platform == 'linux2':
            # linux
            self._tmp_path = '/tmp'

        elif platform == 'darwin':
            # OS X
            self._tmp_path = '/tmp'

        elif platform == 'win32':
            # Windows
            self._tmp_path = 'C://Windows/temp'

        self.__logger.debug('self.tmp_path=%s', self._tmp_path)

    def get_optimal_shard_number(self):
        """
        Returns the optimal number of shards.

        See https://github.com/aleitner/shard-size-calculator/blob/master/src/shard_size.c

        Returns:
            [int]: number of shards.
        """

        shard_size = self.determine_shard_size()
        if shard_size == 0:
            shard_size = self.filesize

        shard_count = int(math.ceil(float(self.filesize) / float(shard_size)))

        self.__logger.debug(
            'shard_size = %d, shard_count = %d, file_size = %d',
            shard_size, shard_count, self.filesize)

        return shard_count

    def determine_shard_size(self, accumulator=0):
        """
        Determine the optimal shard size.

        See https://github.com/aleitner/shard-size-calculator/blob/master/src/shard_size.c

        Args:
            accumulator (int):
        """
        self.__logger.debug('determine_shard_size(%d)', accumulator)

        if self.filesize <= 0:
            return self.filesize

        # Determine hops back by accumulator

        if accumulator - ShardManager.SHARD_MULTIPLES_BACK < 0:
            hops = 0
        else:
            hops = accumulator - ShardManager.SHARD_MULTIPLES_BACK

        byte_multiple = ShardManager.SHARD_SIZE * pow(2, accumulator)
        check = float(self.filesize) / float(byte_multiple)

        self.__logger.debug(
            'hops=%d acumulator = %d check = %.2f file_size = %d byte_multiple = %d',
            hops, accumulator, check, self.filesize, byte_multiple)

        if 0 < check <= 1:
            while hops > 0 and ShardManager.SHARD_SIZE * pow(2, hops) > ShardManager.MAX_SHARD_SIZE:
                if hops - 1 <= 0:
                    hops = 0
                else:
                    hops -= 1

            self.__logger.debug(
                'hops=%d acumulator = %d check = %.2f file_size = %d byte_multiple = %d',
                hops, accumulator, check, self.filesize, byte_multiple)

            return ShardManager.SHARD_SIZE * pow(2, hops)

        # maximum of 2 ^ 41 * 8 * 1024 * 1024 = 16 exabytes
        if accumulator > 41:
            return 0

        accumulator += 1
        return self.determine_shard_size(accumulator)

    def _make_shards(self):
        """Populates the shard manager with shards."""

        if self.num_chunks == 0:
            self.num_chunks = self.get_optimal_shard_number()
        self.__logger.debug('number of chunks %d', self.num_chunks)

        index = 0

        try:
            with open(self.filepath, 'rb') as f:

                bname = os.path.split(self.filepath)[1]
                chunk_size = int(float(self.filesize) / float(self.num_chunks))
                self.__logger.debug('chunk_size = %d', chunk_size)

                for x in range(1, self.num_chunks + 1):
                    chunk_fn = '%s-%s%s' % (bname, x, self.suffix)

                    try:
                        data = f.read(chunk_size)

                        self.__logger.debug('writing file %s', chunk_fn)
                        with open(os.path.join(self.tmp_path, chunk_fn), 'wb') as chunkf:
                            chunkf.write(data)

                        challenges = self._make_challenges(self.nchallenges)

                        self.shards.append(
                            Shard(size=len(data), index=index,
                                  hash=ShardManager.hash(data),
                                  tree=self._make_tree(challenges, data),
                                  challenges=challenges))

                        index += 1

                    except (OSError, IOError) as e:
                        self.__logger.error(e)
                        continue

        except (OSError, IOError) as e:
            self.__logger.error(e)
            raise ShardingException(str(e))

    @staticmethod
    def hash(data):
        """Returns ripemd160 of sha256 of a string as a string of hex.
        Args:
            data (str): content to be digested.
        Returns:
            (str): the ripemd160 of sha256 digest.
        """

        if not isinstance(data, six.binary_type):
            data = bytes(data.encode('utf-8'))

        return binascii.hexlify(ShardManager._ripemd160(ShardManager._sha256(data))).decode('utf-8')

    @staticmethod
    def _ripemd160(b):
        """Returns the ripemd160 digest of bytes as bytes.
        Args:
            b (str): content to be ripemd160 digested.
        Returns:
            (str): the ripemd160 digest.
        """

        return hashlib.new('ripemd160', b).digest()

    @staticmethod
    def _sha256(b):
        """Returns the sha256 digest of bytes as bytes.
        Args:
            b (str): content to be sha256 digested.
        Returns:
            (str): the sha256 digest.
        """

        return hashlib.new('sha256', b).digest()

    def _make_challenges(self, challenges=12):
        """Generates the challenge strings.
        Args:
            challenges (int): number of challenges to be generated.
        Returns:
            (list[str]): list of challenges.
        """
        return [self._make_challenge_string() for _ in xrange(challenges)]

    def _make_challenge_string(self):
        return binascii.hexlify(''.join(os.urandom(32)))

    def _make_tree(self, challenges, data):
        """Creates a Storj Merkle tree.
        Args:
            challenges (list[str]): A list of random challenges.
            data (str): data to be audited.
        Returns:
            (:py:class:`MerkleTree`): audit tree.
        """
        return MerkleTree(ShardManager.hash('%s%s' % (c, data)) for c in challenges)


class Token(Object):
    """Token.

    Args:
        id (str): token unique identifier.
        bucket (str): bucket unique identifier.
        operation ():
        expires (str): expiration date, in the RFC3339 format.
        encryptionKey (str):

    Attributes:
        id (str): token unique identifier.
        bucket (:py:class:`storj.model.Bucket`): bucket.
        operation (str):
        expires (datetime.datetime): expiration date, in UTC.
        encryptionKey (str):
    """

    def __init__(
        self, token=None, bucket=None, operation=None, expires=None,
        encryptionKey=None, id=None,
    ):
        self.token = token
        self.bucket = Bucket(id=bucket)
        self.operation = operation
        self.id = id

        if expires is not None:
            self.expires = datetime.fromtimestamp(
                strict_rfc3339.rfc3339_to_timestamp(expires))
        else:
            self.expires = None

        self.encryptionKey = encryptionKey


class ExchangeReport(Object):
    def __init__(
        self, dataHash=None, reporterId=None, farmerId=None, clientId=None,
        exchangeStart=None, exchangeEnd=None, exchangeResultCode=None, exchangeResultMessage=None
    ):
        self.dataHash = dataHash
        self.reporterId = reporterId
        self.farmerId = farmerId
        self.clientId = clientId
        self.exchangeStart = exchangeStart
        self.exchangeEnd = exchangeEnd
        self.exchangeResultCode = exchangeResultCode
        self.exchangeResultMessage = exchangeResultMessage

        # result codes
        self.SUCCESS = 1000
        self.FAILURE = 1100
        self.STORJ_REPORT_UPLOAD_ERROR = "TRANSFER_FAILED"
        self.STORJ_REPORT_SHARD_UPLOADED = "SHARD_UPLOADED"
        self.STORJ_REPORT_DOWNLOAD_ERROR = "DOWNLOAD_ERROR"
        self.STORJ_REPORT_SHARD_DOWNLOADED = "SHARD_DOWNLOADED"


class StorjParametrs(Object):
    def __init__(
        self, tmpPath=None
    ):
        self.tmpPath = tmpPath
