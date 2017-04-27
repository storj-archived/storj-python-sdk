# -*- coding: utf-8 -*-
"""Storj API bucket endpoint integration tests."""

import logging

import pytest


from storj.exception import BridgeError

from . import Integration


class Bucket(Integration):
    """Test case for the bucket endpoint.

    Attributes:
        bucket (:py:class:`storj.models.Bucket`: test bucket.
    """

    logger = logging.getLogger('%s.Bucket' % __name__)

    def setUp(self):
        """Setup test bucket."""
        super(Bucket, self).setUp()
        self.bucket = self.client.bucket_create(
            'integration-%s' % self.test_id)

    def tearDown(self):
        """Destroy test bucket."""
        super(Bucket, self).tearDown()
        try:
            self.client.bucket_delete(self.bucket.id)
        except BridgeError as e:
            self.logger.error(e)

    def test(self):
        """Test:

        1. after setup
        1.1 get retrieves the bucket
        1.2 list has bucket

        2. delete bucket
        2.1 get does not retrieve the bucket
        2.2 list does not have bucket
        """
        self.logger.debug('---------- test() ----------')

        self.logger.debug('1.1')
        assert self.bucket == self.client.bucket_get(self.bucket.id)

        self.logger.debug('1.2')
        assert self.bucket in self.client.bucket_list()

        self.logger.debug('2.')
        self.client.bucket_delete(self.bucket.id)

        self.logger.debug('2.1')
        with pytest.raises(BridgeError):
            self.client.bucket_get(self.bucket.id)

        self.logger.debug('2.2')
        with pytest.raises(StopIteration):
            next(self.client.bucket_list())
