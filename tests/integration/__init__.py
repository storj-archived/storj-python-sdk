# -*- coding: utf-8 -*-
"""Storj API integration tests."""

import sys
import os

from abc import ABCMeta

from .. import AbstractTestCase


ENV_STORJ_EMAIL = 'STORJ_EMAIL'
ENV_STORJ_PASSWORD = 'STORJ_PASSWORD'


class Integration(AbstractTestCase):
    """Abstract class for integration tests."""
    __metaclass__ = ABCMeta

    def __init__(self, methodName):
        super(AbstractTestCase, self).__init__(methodName)

        try:
            self.email = os.environ[ENV_STORJ_EMAIL]
            self.password = os.environ[ENV_STORJ_PASSWORD]
        except KeyError as e:
            self.logger.error(e)
            self.logger.error(
                'To run integration tests you need to define the following environment variables: %s, %s.' % (
                    ENV_STORJ_EMAIL, ENV_STORJ_PASSWORD))
            sys.exit(os.EX_CONFIG)
