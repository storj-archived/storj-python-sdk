# -*- coding: utf-8 -*-
"""Test logging module."""

import os

import logging
import logging.config as config


DEFAULT_CONFIG_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), 'logging.conf')


def load_configuration(config_file=DEFAULT_CONFIG_FILE):
    """
    Loads logging configuration from the given configuration file.

    :param config_file:
        the configuration file (default=/etc/package/logging.conf)
    :type config_file: str
    """
    if not os.path.exists(config_file) or not os.path.isfile(config_file):
        msg = '%s configuration file does not exist!', config_file
        logging.getLogger(__name__).error(msg)
        raise ValueError(msg)

    try:
        config.fileConfig(config_file, disable_existing_loggers=False)
        logging.getLogger(__name__).info(
            '%s configuration file was loaded.', config_file)
    except Exception as e:
        logging.getLogger(__name__).error(
            'Failed to load configuration from %s!', config_file)
        logging.getLogger(__name__).debug(str(e), exc_info=True)
        raise e
