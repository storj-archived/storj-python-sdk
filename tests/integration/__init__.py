# -*- coding: utf-8 -*-
"""Storj API integration tests."""

import os

from datetime import datetime
from storj import http

from .. import AbstractTestCase


#: name of the environment variable that contains the Storj account email.
ENV_STORJ_EMAIL = 'STORJ_EMAIL'
#: name of the environment variable that contains the Storj account password.
ENV_STORJ_PASSWORD = 'STORJ_PASSWORD'


class Integration(AbstractTestCase):
    """Base class for integration tests.

    Attributes:
        email (str): Storj account email.
        password (str): Storj account password.
        client (:py:class:`storj.http.Client`): HTTP client.
        test_id (str): unique identifier to be appended to temporary resources.
    """

    def __init__(self, methodName):
        super(Integration, self).__init__(methodName)

        try:
            self.email = os.environ[ENV_STORJ_EMAIL]
            self.password = os.environ[ENV_STORJ_PASSWORD]
        except KeyError as e:
            self.logger.error(e)
            msg = (
                'To run integration tests you need to define '
                'the following environment variables: %s, %s.'
            )
            err_msg = msg % (
                ENV_STORJ_EMAIL, ENV_STORJ_PASSWORD
            )
            self.logger.error(err_msg)
            self.fail(err_msg)

    def setUp(self):
        super(Integration, self).setUp()
        self.client = http.Client(self.email, self.password)
        self.test_id = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
