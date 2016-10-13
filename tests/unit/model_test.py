# -*- coding: utf-8 -*-
"""Test cases for the storj.model module."""

import strict_rfc3339


from datetime import datetime

from storj.model import Bucket, Frame, Shard

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
            AssertionError: in case one of the Shard attributes is not set as expected.
        """

        shard = Shard(**kwargs)

        assert kwargs['challenges'] if 'challenges' in kwargs else [] == shard.challenges
        assert kwargs['exclude'] if 'exclude' in kwargs else [] == shard.exclude

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
