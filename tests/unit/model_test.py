# -*- coding: utf-8 -*-
"""Test cases for the storj.model module."""

from sys import platform

import mock
import pytest
import shutil
import six
import strict_rfc3339
import tempfile

from datetime import datetime

from pycoin.key.Key import Key

from storj.model import \
    Bucket, Contact, File, FilePointer, Frame, KeyPair, \
    MerkleTree, Mirror, Shard, ShardManager, Token, IdecdsaCipher

from .. import AbstractTestCase


class BucketTestCase(AbstractTestCase):
    """Test case for the Bucket class."""

    def test_init(self):
        """Test Bucket.__init__()."""
        kwargs = dict(
            created='2016-10-13T04:23:48.183Z',
            id='510b23e9f63a77d939a72a77',
            name='integration-20161013_042347',
            pubkeys=[],
            status='Active',
            storage=0,
            transfer=0,
            user='steenzout@ymail.com')

        bucket = Bucket(**kwargs)

        assert bucket.created == datetime.fromtimestamp(
            strict_rfc3339.rfc3339_to_timestamp(
                '2016-10-13T04:23:48.183Z'))
        assert bucket.id == '510b23e9f63a77d939a72a77'
        assert bucket.name == 'integration-20161013_042347'
        assert bucket.pubkeys == []
        assert bucket.status == 'Active'
        assert bucket.storage == 0
        assert bucket.transfer == 0
        assert bucket.user == 'steenzout@ymail.com'


class ContactTestCase(AbstractTestCase):
    """Test case for the Contact class."""

    def test_init(self):
        """Test Contact.__init__()."""

        kwargs = dict(
            address='api.storj.io',
            port=8443,
            nodeID='32033d2dc11b877df4b1caefbffba06495ae6b18',
            lastSeen='2016-05-24T15:16:01.139Z',
            protocol='0.7.0',
            userAgent='4.0.3'
        )

        contact = Contact(**kwargs)

        assert contact.address == kwargs['address']
        assert contact.port == kwargs['port']
        assert contact.nodeID == kwargs['nodeID']
        assert contact.lastSeen == datetime.fromtimestamp(
            strict_rfc3339.rfc3339_to_timestamp(kwargs['lastSeen']))
        assert contact.protocol == kwargs['protocol']
        assert contact.userAgent == kwargs['userAgent']


class FileTestCase(AbstractTestCase):
    """Test case for the File class."""

    def test_init(self):
        """Test File.__init__()."""

        kwargs = dict(
            bucket='bucket_id',
            hash='hash',
            mimetype='mimetype',
            filename='filename',
            frame='frame_id'
        )

        f = File(**kwargs)

        assert f.bucket == Bucket(id=kwargs['bucket'])
        assert f.hash == kwargs['hash']
        assert f.mimetype == kwargs['mimetype']
        assert f.filename == kwargs['filename']
        assert f.frame == Frame(id=kwargs['frame'])
        assert f.shard_manager is None


class FilePointerTestCase(AbstractTestCase):
    """Test case for the FilePointer class."""

    def test_init(self):
        """Test File.__init__()."""

        # https://storj.github.io/bridge/#!/buckets/get_buckets_id_files_file_id
        kwargs = dict(
            hash='ba084d3f143f2896809d3f1d7dffed472b39d8de',
            token='99cf1af00b552113a856f8ef44f58d22269389e8'
                  '009d292bafd10af7cc30dcfa',
            operation='PULL',
            channel='ws://farmer.hostname:4000'
        )

        fp = FilePointer(**kwargs)

        assert fp.hash == kwargs['hash']
        assert fp.token == Token(id=kwargs['token'])
        assert fp.operation == kwargs['operation']
        assert fp.channel == kwargs['channel']


class FrameTestCase(AbstractTestCase):
    """Test case for the Frame class."""

    def test_init(self):
        """Test Frame.__init__()."""
        kwargs = dict(
            created='2016-10-13T04:23:48.183Z',
            id='510b23e9f63a77d939a72a77',
            shards=[])

        frame = Frame(**kwargs)

        assert frame.created == datetime.fromtimestamp(
            strict_rfc3339.rfc3339_to_timestamp(
                '2016-10-13T04:23:48.183Z'))
        assert frame.id == '510b23e9f63a77d939a72a77'
        assert frame.shards == []


class KeyPairTestCase(AbstractTestCase):
    """Test case for the KeyPair class."""

    def _assert_wallet(self, wallet):
        assert isinstance(wallet.keypair, Key)
        assert wallet.private_key == self.private_key
        assert wallet.public_key == self.public_key
        assert wallet.node_id == 'abb5b062c7797924bb5b7d65e4f8a2f7c6e0311f'
        assert wallet.address == '1GevCn3H1p76GHHPS9nzg8wBYLFaS2MAmX'

    def setUp(self):
        self.master_password = 'master_password'
        self.secret = (
            'c7d360e0d7d6820ea8d33cc7ad81bf9d'
            '04c2f9c793f21cbf0a4a004350346ab8'
        )
        self.secret_exponent = int(self.secret, 16)
        self.private_key = (
            'c7d360e0d7d6820ea8d33cc7ad81bf9d'
            '04c2f9c793f21cbf0a4a004350346ab8'
        )
        self.public_key = (
            '03980352d67d91a8cf64251b1d4f72726'
            '54c70aa21932aaea1b359c47b26aee9d0'
        )

    def test_init(self):
        """Test KeyPair.__init__()."""

        self._assert_wallet(KeyPair(**dict(
            pkey=self.secret
        )))
        self._assert_wallet(KeyPair(**dict(secret=self.master_password)))


class IdecdsaCipherTestCase(AbstractTestCase):
    """Test case for the IdecdsaCipher class."""

    def test_encrypt_decrypt(self):
        password = 'testpassword'
        data = ('c7d360e0d7d6820ea8d33cc7ad81bf9d'
                '04c2f9c793f21cbf0a4a004350346ab8')

        cipher = IdecdsaCipher()

        assert cipher.simpleDecrypt(
            password, cipher.simpleEncrypt(password, data)) == data

        bytes_data = 'testpassword'.encode('utf-8')
        assert cipher.simpleDecrypt(
            password, cipher.simpleEncrypt(password, bytes_data)) == bytes_data

    def test_pad_unpad(self):
        data = '0123456789abcdef'

        assert data == IdecdsaCipher.unpad(IdecdsaCipher.pad(data))

        data = b'0123456789abcdef'

        assert data == IdecdsaCipher.unpad(IdecdsaCipher.pad(data))

    def test_bytes_to_key(self):
        password = 'secret'
        cipher = IdecdsaCipher()

        assert ('^\xbe"\x94\xec\xd0\xe0\xf0\x8e\xab',
                'v\x90\xd2\xa6\xeei&\xae\\\xc8T\xe3kk\xdf\xca6hH\xde') == \
            cipher.EVP_BytesToKey(password, 10, 20)


class MirrorTestCase(AbstractTestCase):
    """Test case for the Mirror class."""

    def test_init(self):
        """Test Mirror.__init__()."""

        kwargs = dict(
            hash='fde400fe0b6a5488e10d7317274a096aaa57914d',
            mirrors=3,
            status='pending')

        mirror = Mirror(**kwargs)

        assert mirror.hash == kwargs['hash']
        assert mirror.mirrors == kwargs['mirrors']
        assert mirror.status == kwargs['status']


class ShardTestCase(AbstractTestCase):
    """Test case for the Shard class."""

    def _assert_init(self, kwargs):
        """Run __init__ assertions.

        Args:
            kwargs (dict): keyword arguments for the Shard initializer.

        Raises:
            AssertionError: Shard attributes is not set as expected.
        """

        shard = Shard(**kwargs)

        if 'challenges' in kwargs:
            assert kwargs['challenges']
        else:
            assert shard.challenges == []

        if 'exclude' in kwargs:
            assert kwargs['exclude']
        else:
            assert shard.exclude == []

        assert shard.hash == kwargs['hash']
        assert shard.id == kwargs['id']
        assert shard.index == kwargs['index']

        assert shard.size is None

        assert kwargs['tree'] if 'tree' in kwargs else [] == shard.tree

    def test_init(self):
        """Test Shard.__init__()."""

        kwargs = dict(
            hash='',
            id='510b23e9f63a77d939a72a77',
            index=0)
        self._assert_init(kwargs)

        kwargs = dict(
            challenges=['abc'],
            exclude=['abc'],
            hash='',
            id='510b23e9f63a77d939a72a77',
            index=1,
            tree=['abc'])
        self._assert_init(kwargs)

    def test_add_challenge(self):
        """Test Shard.add_challenge()."""

        shard = Shard()
        shard.add_challenge('challenge1')

        assert shard.challenges == ['challenge1']

    def test_add_tree(self):
        """Test Shard.add_tree()."""

        shard = Shard()
        shard.add_tree('node')

        assert shard.tree == ['node']

    def test_get_public_record(self):
        pass

    def test_get_private_record(self):
        pass


class ShardManagerTestCase(AbstractTestCase):
    """Test case for the ShardManager class."""

    GB = 1024 * 1024 * 1024

    def _assert_init(self, args, kwargs, file_size):

        shard_manager = ShardManager(*args, **kwargs)

        assert shard_manager.filepath == args[0]

        if 'tmp_path' in kwargs:
            assert shard_manager.tmp_path == kwargs['tmp_path']

        elif platform == 'linux' or platform == 'linux2':
            assert shard_manager.tmp_path == '/tmp'

        elif platform == 'darwin':
            assert shard_manager.tmp_path == '/tmp'

        elif platform == 'win32':
            assert shard_manager.tmp_path == 'C://Windows/temp'

        if 'suffix' in kwargs:
            assert shard_manager.suffix == kwargs['suffix']
        else:
            assert shard_manager.suffix == ''

        assert shard_manager.filesize == file_size

    @mock.patch('storj.model.ShardManager._make_shards')
    @mock.patch('storj.model.os.stat')
    @mock.patch('storj.model.os.path.exists')
    @mock.patch('storj.model.os.path.isfile')
    def test_init(self, mock_isfile, mock_exists, mock_stat, mock_shards):

        mock_isfile.return_value = True
        mock_exists.return_value = True
        file_size = 10 * 1024 * 1024
        mock_stat.return_value = mock.Mock(st_size=file_size)
        mock_shards.return_value = None

        for args, kwargs in [
            (('/somewhere',), {}),
            (('/somewhere',), {'tmp_path': '/dev/null', 'suffix': 'csj'}),
        ]:
            self._assert_init(args, kwargs, file_size)

            assert mock_isfile.assert_called
            mock_isfile.called_once_with(args[0])

            assert mock_exists.assert_called
            mock_exists.called_once_with(args[0])

            assert mock_stat.assert_called
            mock_stat.called_once_with(args[0])

    @mock.patch.object(ShardManager, '_make_challenges', return_value=[])
    @mock.patch.object(ShardManager, '_make_tree', return_value=[])
    def test_property_file_path(self, mock_tree, mock_challenges):
        """Test filepath property."""

        # file path is not a str
        with pytest.raises(ValueError):
            ShardManager(1, 1)

        # file path does not exist
        with pytest.raises(ValueError):
            ShardManager('/dev/nowhere', 1)

        # file path is a directory
        tmpdir = tempfile.mkdtemp()
        try:
            with pytest.raises(ValueError):
                ShardManager(tmpdir, 1)
        finally:
            shutil.rmtree(tmpdir)

        # file path is a text file
        content = '1234567890'
        self._assert_shard_manager(
            content, 'w+t', mock_tree, mock_challenges)

        content = b'1234567890'
        self._assert_shard_manager(
            content, 'w+b', mock_tree, mock_challenges)

    def _assert_shard_manager(self, content, mode, mock_tree, mock_challenges):
        with tempfile.NamedTemporaryFile(mode, delete=False) as tmp_file:
            tmp_file.write(content)
            tmp_file.flush()

            nchallenges = 2
            sm = ShardManager(
                tmp_file.name,
                nchallenges=nchallenges)

            assert sm.filepath == tmp_file.name
            assert len(sm.shards) > 0

        mock_challenges.assert_called_once_with(nchallenges)
        if isinstance(content, six.binary_type):
            mock_tree.assert_called_once_with(
                mock_challenges.return_value, content)
        else:
            mock_tree.assert_called_once_with(
                mock_challenges.return_value, bytes(content.encode('utf-8')))

        mock_tree.reset_mock()
        mock_challenges.reset_mock()

    def test_get_optimal_shard_number(self):
        """Test ShardManager.get_optimal_shard_number()."""
        shard_manager = ShardManager(__file__)

        for file_size, expected_shard_size, expected_shard_count in [
            # (file size, shard size, shard count)
            (43 * self.GB, 4 * self.GB, 11)
        ]:
            shard_manager._filesize = file_size
            shard_count = \
                shard_manager.get_optimal_shard_number()

            assert expected_shard_count == shard_count

    @mock.patch.object(ShardManager, '_sha256')
    @mock.patch.object(ShardManager, '_ripemd160')
    @mock.patch('storj.model.bytes')
    @mock.patch('storj.model.binascii')
    def test_hash(self,
                  mock_binascii, mock_bytes, mock_ripemd160, mock_sha256):
        """Test ShardManager.hash()"""

        hash_output = mock.MagicMock()
        test_data = mock.MagicMock()
        test_data.encode.return_value = test_data

        mock_ripemd160.return_value = hash_output
        mock_sha256.return_value = hash_output

        mock_bytes.return_value = test_data
        mock_binascii.hexlify.return_value = test_data

        output = ShardManager.hash(test_data)

        assert output is not None

        test_data.encode.assert_called_with('utf-8')
        mock_bytes.assert_called_with(test_data)
        mock_sha256.assert_called_with(test_data)
        mock_ripemd160.assert_called_with(hash_output)
        mock_binascii.hexlify.assert_called_with(hash_output)
        test_data.decode.assert_called_with('utf-8')

    @mock.patch('storj.model.hashlib')
    def test_ripemd160_binary(self, mock_hashlib):
        """Test ShardManager._ripemd160"""
        test_data = b'ab'

        output = ShardManager._ripemd160(test_data)

        assert output is not None

        mock_hashlib.new.assert_called_with('ripemd160', test_data)
        mock_hashlib.new.return_value.digest.assert_called_once_with()

    @mock.patch('storj.model.hashlib')
    def test_ripemd160_text(self, mock_hashlib):
        """Test ShardManager._ripemd160"""

        test_data = 'ab'

        output = ShardManager._ripemd160(test_data)

        assert output is not None

        mock_hashlib.new.assert_called_with('ripemd160', test_data)
        mock_hashlib.new.return_value.digest.assert_called_once_with()

    @mock.patch('storj.model.hashlib')
    def test_sha256_binary(self, mock_hashlib):
        """Test ShardManager._sha256"""
        test_data = b'ab'

        output = ShardManager._ripemd160(test_data)

        mock_hashlib.new.assert_called_with('ripemd160', test_data)
        mock_hashlib.new.return_value.digest.assert_called_once_with()

    @mock.patch('storj.model.hashlib')
    def test_sha256_text(self, mock_hashlib):
        """Test ShardManager._sha256"""
        test_data = 'ab'

        output = ShardManager._ripemd160(test_data)

        mock_hashlib.new.assert_called_with('ripemd160', test_data)
        mock_hashlib.new.return_value.digest.assert_called_once_with()


class TokenTestCase(AbstractTestCase):
    """Test case for the Token class."""

    def _assert_init(self, kwargs):
        """Run __init__ assertions.

        Args:
            kwargs (dict): keyword arguments for the Token initializer.

        Raises:
            AssertionError: Token attributes is not set as expected.
        """

        token = Token(**kwargs)

        if 'bucket' in kwargs:
            assert token.bucket.id == kwargs['bucket']
        else:
            assert token.bucket is None

        if 'expires' in kwargs:
            assert token.expires == datetime.fromtimestamp(
                strict_rfc3339.rfc3339_to_timestamp(
                    kwargs['expires']))
        else:
            assert token.expires is None

        if 'operation' in kwargs:
            assert token.operation == kwargs['operation']
        else:
            assert token.operation is None

        if 'id' in kwargs:
            assert token.id == kwargs['id']
        else:
            assert token.id is None

    def test_init(self):
        """Test Token.__init__()."""
        kwargs = dict(
            bucket='',
            expires='2016-10-13T04:23:48.183Z',
            operation='unknown',
            id='510b23e9f63a77d939a72a77')
        self._assert_init(kwargs)

        kwargs = dict(
            bucket='',
            expires='2016-10-13T04:23:48.183Z',
            operation='unknown',
            id='510b23e9f63a77d939a72a77')
        self._assert_init(kwargs)


class MerkleTreeTestCase(AbstractTestCase):
    """Test case for the MerkleTree Class"""

    def setUp(self):
        super(AbstractTestCase, self).setUp()

        self.leaves = ['a', 'b', 'c', 'd']
        self.tree = MerkleTree(self.leaves)

    def _assert_init(self, leaves, mock_generate, kwargs):
        """Run init assertions for MerkleTree."""

        tree = MerkleTree(leaves, **kwargs)

        assert tree.leaves == ['a', 'b']

        prehashed = kwargs['prehashed'] if 'prehashed' in kwargs else True
        assert prehashed == tree.prehashed

        assert tree.count == 0
        assert tree._rows == []
        assert tree.depth == 1

        mock_generate.assert_called_once_with()
        mock_generate.reset_mock()

    @mock.patch.object(MerkleTree, '_generate')
    def test_init(self, mock_generate):
        """Test MerkleTree.__init__()."""

        # success
        for leaves, kwargs in (
            (['a', 'b'], dict()),
            (['a', 'b'], dict(prehashed=True)),
            ((x for x in ['a', 'b']), dict())
        ):
            self._assert_init(leaves, mock_generate, kwargs)

        # failure
        for leaves in (None, 73, [], [1, 2]):
            with self.assertRaises(ValueError):
                self._assert_init(leaves, mock_generate, {})
                assert not mock_generate.called

    def test_generate(self):
        """Test MerkleTree._generate()"""
        self.tree._make_row = mock.MagicMock()
        self.tree._make_row.return_value = ['a', 'b']

        self.tree._generate()

        make_row_calls = [mock.call(1), mock.call(0)]
        self.tree._make_row.assert_has_calls(make_row_calls)

    @mock.patch.object(ShardManager, 'hash', return_value='7')
    def test_make_row(self, mock_hash):
        """Test MerkleTree._make_row()"""

        self.tree._rows = [[],
                           [],
                           ['a', 'b', 'c', 'd']]

        row = self.tree._make_row(1)

        calls = [mock.call('ab'),
                 mock.call('cd')]
        mock_hash.assert_has_calls(calls)
        self.assertEqual(row, ['7', '7'])

    def test_property_depth(self):
        """Test depth property."""

        self.tree._leaves = mock.MagicMock()
        self.tree._leaves.__len__.return_value = 8

        depth = self.tree.depth

        self.assertEqual(self.tree.leaves.__len__.call_count, 4)
        self.assertEqual(2 ** depth, 8)

    def test_get_root(self):
        """Test MerkleTree.get_root"""
        root = self.tree.get_root()

        self.assertEqual(root, self.tree._rows[0][0])

    def test_get_level(self):
        """Test MerkleTree.get_level"""
        level = self.tree.get_level(1)

        self.assertEqual(level, self.tree._rows[1])

    def test_node_output(self):
        """Test MerkleTree with output from the node client"""

        leaves = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h']
        depth = 3
        rows = [[
            '2adf050f14bf6324bfd41577d0dc08e2e49766fa'
        ], [
            '39c096fc1b11e77f4347cfdb45ba9b03c0ad95d9',
            '47121e7ec10e7653f1262b1d3abb6f9a71b3de8b'
        ], [
            'e4973182d0c331ce8b083ffa2b28c8b4fc0f1d93',
            'c91b9f3b2937035cc07d3fcd258d7d8a1f0c4d3c',
            '8182daac9a266aa39328b835726f80a34835027d',
            '222025114b2d1374b4a354d1b4452f648c9b481d'
        ], [
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'
        ]]
        count = 7

        tree = MerkleTree(leaves)

        self.assertEqual(tree.leaves, leaves)
        self.assertEqual(tree.depth, depth)
        self.assertEqual(tree._rows, rows)
        self.assertEqual(tree.count, count)
