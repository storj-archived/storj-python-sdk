# -*- coding: utf-8 -*-
"""Storj API bucket endpoint integration tests."""

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
        1.1 get does not retrieve the bucket
        1.2 list does not have bucket
        """
        assert self.bucket == self.client.bucket_get(self.bucket.id)

        assert self.bucket in self.client.bucket_list()

        self.client.bucket_delete(self.bucket.id)

        assert self.client.bucket_get(self.bucket.id) is None

        assert [] == self.client.bucket_list()
