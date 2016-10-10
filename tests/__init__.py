# -*- coding: utf-8 -*-
"""Storj tests."""

import logging
import unittest


from abc import ABCMeta

from . import config
from . import log_config


config.load_configuration()
log_config.load_configuration()


class Basic(object):
    """Basic functionality to enhance test cases.

    Attributes:
        configuration ():
        logger (): logger.
    """
    __metaclass__ = ABCMeta

    def setup_configuration(self):
        """
        Setup test configuration.
        It will also load (once) the test configuration.
        """
        logging.getLogger(
            '%s.%s' % (__name__, 'Basic')).info('setup_configuration()')

        self.configuration = config.get()

    def setup_logger(self):
        """
        Setup test logger.
        It will also load (once) the test logging configuration.
        """
        logging.getLogger('%s.%s' % (__name__, 'Basic')).info('setup_logger()')

        self.logger = logging.getLogger(
            '%s.%s' % (__name__, self.__class__.__name__))


class AbstractTestCase(unittest.TestCase, Basic):
    """Base test case."""
    __metaclass__ = ABCMeta

    __slots__ = ('configuration', 'logger')

    def __init__(self, methodName):
        """Initializes a BaseTestCase instance.

        Args:
            methodName (str): the test method to be executed.
        """
        super(AbstractTestCase, self).__init__(methodName)

        self.setup_logger()
        self.setup_configuration()

    def setUp(self):
        """Setup test resources."""
        self.logger.info('setUp()')

    def tearDown(self):
        """Tear down test resources."""
        self.logger.info('tearDown()')
