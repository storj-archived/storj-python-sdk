# -*- coding: utf-8 -*-
"""Storj API bucket endpoint integration tests."""

import pytest


from . import Integration


class Bucket(Integration):
    """Test case for the bucket endpoint.

    Attributes:
        bucket (:py:class:`storj.models.Bucket`: test bucket.
    """

    def setUp(self):
        """Setup test bucket."""
        super(Bucket, self).setUp()
        self.bucket = self.client.bucket_create('integration-%s' % self.test_id)

    def tearDown(self):
        """Destroy test bucket."""
        super(Bucket, self).tearDown()
        self.client.bucket_delete(self.bucket.id)

    def test(self):
        """Test:

        1. after setup
        1.1 get retrieves the bucket
        1.2 list has bucket

        2. delete bucket
        2.1 get does not retrieve the bucket
        2.2 list does not have bucket
        """
        self.logger.debug('---------- %s.test() ----------' % __name__)

        self.logger.debug('%s 1.1' % __name__)
        assert self.bucket == self.client.bucket_get(self.bucket.id)

        self.logger.debug('%s 1.2' % __name__)
        assert self.bucket in self.client.bucket_list()

        self.logger.debug('%s 2.' % __name__)
        self.client.bucket_delete(self.bucket.id)

        self.logger.debug('%s 2.1' % __name__)
        assert self.client.bucket_get(self.bucket.id) is None

        self.logger.debug('%s 2.2' % __name__)
        with pytest.raises(StopIteration):
            self.client.bucket_list().next()
