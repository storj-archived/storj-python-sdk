# -*- coding: utf-8 -*-
"""Test cases for the storj.http module."""

import mock

import storj


from .. import AbstractTestCase


class FunctionsTestCase(AbstractTestCase):
    """Test case for the module functions."""

    @mock.patch('storj.configuration.click.get_app_dir')
    @mock.patch('storj.configuration.configparser.RawConfigParser')
    def test_read_config(self, mock_class_rawconfigparser, mock_app_dir):
        # mock instance for ConfigParser.RawConfigParser
        mrcp = mock_class_rawconfigparser.return_value
        mrcp.read.return_value = None
        mrcp.sections.return_value = ['storj']
        mrcp.items.return_value = {
            'email': 'someone@example.com',
            'password': 'secret'
        }.items()

        mock_app_dir.return_value = '/nowhere'

        assert storj.configuration.read_config() == {
            storj.CFG_EMAIL: 'someone@example.com',
            storj.CFG_PASSWORD: 'secret'
        }

        mrcp.read.assert_called_once_with(['/nowhere/storj.ini'])
        mrcp.sections.assert_called_once_with()
        mrcp.items.assert_called_once_with('storj')
