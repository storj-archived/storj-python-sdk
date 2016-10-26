# -*- coding: utf-8 -*-
"""Test cases for the storj.model module."""

import strict_rfc3339


from datetime import datetime

from storj.model import Bucket, Frame, Shard, Token, MerkleTree
import mock

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

        assert kwargs['challenges'] if 'challenges' in kwargs else [
        ] == shard.challenges
        assert kwargs[
            'exclude'] if 'exclude' in kwargs else [] == shard.exclude

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
            index='')
        self._assert_init(kwargs)

        kwargs = dict(
            challenges=['abc'],
            exclude=['abc'],
            hash='',
            id='510b23e9f63a77d939a72a77',
            index='',
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
            assert token.bucket_id == kwargs['bucket']
        else:
            assert token.bucket_id is None

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

        if 'token' in kwargs:
            assert token.id == kwargs['token']
        else:
            assert token.id is None

    def test_init(self):
        """Test Token.__init__()."""
        kwargs = dict(
            bucket='',
            expires='2016-10-13T04:23:48.183Z',
            operation='unknown',
            token='510b23e9f63a77d939a72a77')
        self._assert_init(kwargs)

        kwargs = dict(
            bucket='',
            expires='2016-10-13T04:23:48.183Z',
            operation='unknown',
            token='510b23e9f63a77d939a72a77')
        self._assert_init(kwargs)


class MerkleTreeTestCase(AbstractTestCase):
    """Test case for the MerkleTree Class"""

    def setUp(self):
        super(AbstractTestCase, self).setUp()

        self.leaves = ['a', 'b', 'c', 'd']
        self.tree = MerkleTree(self.leaves)

    @mock.patch('storj.model.MerkleTree._calculate_depth')
    @mock.patch('storj.model.MerkleTree._generate')
    def _assert_init(self, kwargs, mock_generate, mock_depth):
        """Run init assertions for MerkleTree"""

        mock_depth.return_value = 7
        tree = MerkleTree(**kwargs)

        assert kwargs['leaves'] == tree.leaves

        prehashed = kwargs['prehashed'] if 'prehashed' in kwargs else True
        assert prehashed == tree.prehashed
        assert tree.depth == mock_depth.return_value
        assert tree.count == 0
        assert tree._rows == []

        mock_depth.assert_called_once_with()
        mock_generate.assert_called_once_with()

    def test_init(self):
        """Test MerkleTree.__init__()."""
        kwargs = dict(
            leaves=['a', 'b'],
        )
        self._assert_init(kwargs)

        kwargs = dict(
            leaves=['a', 'b'],
            prehashed=True
        )
        self._assert_init(kwargs)

        kwargs = dict(leaves=73)
        with self.assertRaises(ValueError):
            self._assert_init(kwargs)

        kwargs = dict(leaves=[])
        with self.assertRaises(ValueError):
            self._assert_init(kwargs)

        kwargs = dict(leaves=[1, 2])
        with self.assertRaises(ValueError):
            self._assert_init(kwargs)

    def test_generate(self):
        """Test MerkleTree._generate()"""
        self.tree._make_row = mock.MagicMock()
        self.tree._make_row.return_value = ['a', 'b']

        self.tree._generate()

        make_row_calls = [mock.call(1), mock.call(0)]
        self.tree._make_row.assert_has_calls(make_row_calls)

    def test_make_row(self):
        """Test MerkleTree._make_row()"""

        self.tree._rows = [[],
                           [],
                           ['a', 'b', 'c', 'd']]
        self.tree._hash = mock.MagicMock()
        self.tree._hash.return_value = '7'

        row = self.tree._make_row(1)

        calls = [mock.call('ab'),
                 mock.call('cd')]
        self.tree._hash.assert_has_calls(calls)
        self.assertEqual(row, ['7', '7'])

    @mock.patch('storj.model.bytes')
    @mock.patch('storj.model.binascii')
    def test_hash(self, mock_binascii, mock_bytes):
        """Test MerkleTree._hash()"""

        self.tree._ripemd160 = mock.MagicMock()
        self.tree._sha256 = mock.MagicMock()
        hash_output = mock.MagicMock()
        test_data = mock.MagicMock()

        test_data.encode.return_value = test_data
        self.tree._ripemd160.return_value = hash_output
        self.tree._sha256.return_value = hash_output
        mock_bytes.return_value = test_data
        mock_binascii.hexlify.return_value = test_data

        output = self.tree._hash(test_data)

        test_data.encode.assert_called_with('utf-8')
        mock_bytes.assert_called_with(test_data)
        self.tree._sha256.assert_called_with(test_data)
        self.tree._ripemd160.assert_called_with(hash_output)
        mock_binascii.hexlify.assert_called_with(hash_output)
        test_data.decode.assert_called_with('utf-8')

    @mock.patch('storj.model.hashlib')
    def test_ripemd160(self, mock_hashlib):
        """Test MerkleTree._ripemd160"""
        test_data = 'ab'

        output = self.tree._ripemd160(test_data)

        mock_hashlib.new.assert_called_with('ripemd160', test_data)
        mock_hashlib.new.return_value.digest.assert_called_once_with()

    @mock.patch('storj.model.hashlib')
    def test_sha256(self, mock_hashlib):
        """Test MerkleTree._sha256"""
        test_data = 'ab'

        output = self.tree._ripemd160(test_data)

        mock_hashlib.new.assert_called_with('ripemd160', test_data)
        mock_hashlib.new.return_value.digest.assert_called_once_with()

    def test_calculate_depth(self):
        """Test MerkleTree.calculate_depth"""

        self.tree.leaves = mock.MagicMock()
        self.tree.leaves.__len__.return_value = 8

        depth = self.tree._calculate_depth()

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
