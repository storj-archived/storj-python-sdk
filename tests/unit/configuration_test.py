# -*- coding: utf-8 -*-
"""Test cases for the storj.http module."""

import mock

import storj
import storj.configuration

from .. import AbstractTestCase


class FunctionsTestCase(AbstractTestCase):
    """Test case for the module functions."""

    @mock.patch('storj.configuration.click.get_app_dir')
    @mock.patch.object(storj.configuration.RawConfigParser, 'read')
    @mock.patch.object(storj.configuration.RawConfigParser, 'get')
    def test_read_config(self, mock_get, mock_read, mock_app_dir):
        # mock instance for ConfigParser.RawConfigParser
        mock_read.return_value = None
        mock_get.return_value = ['storj']
        mock_get.side_effect = [
            'someone@example.com',
            'secret'
        ]

        mock_app_dir.return_value = '/nowhere'

        assert storj.configuration.read_config() == (
            'someone@example.com',
            'secret'
        )

        mock_read.assert_called_once_with(['/nowhere/storj.ini'])
        calls = [
            mock.call('storj', 'email'),
            mock.call('storj', 'password'),
        ]
        mock_get.assert_has_calls(calls)
