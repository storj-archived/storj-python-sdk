# -*- coding: utf-8 -*-
"""Test cases for the storj.cli package."""

import logging
import mock

from datetime import datetime
from hashlib import sha256

from click.testing import CliRunner

from storj import cli, model

from .. import AbstractTestCase


class FunctionsTestCase(AbstractTestCase):
    """Test case for the package functions."""

    @mock.patch('storj.cli.read_config')
    def test_get_client(self, mock_read_config):
        mock_read_config.return_value = {
            cli.CFG_EMAIL: 'someone@example.com',
            cli.CFG_PASSWORD: 'secret'
        }

        client = cli.get_client()

        assert client is not None
        assert client.email == 'someone@example.com'
        assert client.password == sha256('secret'.encode('ascii')).hexdigest()

        mock_read_config.assert_called_once_with()

    @mock.patch('storj.cli.click.get_app_dir')
    @mock.patch('storj.cli.configparser.RawConfigParser')
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

        assert cli.read_config() == {
            cli.CFG_EMAIL: 'someone@example.com',
            cli.CFG_PASSWORD: 'secret'
        }

        mrcp.read.assert_called_once_with(['/nowhere/storj.ini'])
        mrcp.sections.assert_called_once_with()
        mrcp.items.assert_called_once_with('storj')


class BucketTestCase(AbstractTestCase):
    """Test case for bucket commands."""

    logger = logging.getLogger('%s.Client' % __name__)
    runner = CliRunner()

    def setUp(self):
        self.timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')

        self.bucket = model.Bucket(
            id='id-%s' % self.timestamp, name='bucket-%s' % self.timestamp,
            storage=100, transfer=100)

    @mock.patch.object(cli.Client, 'bucket_create')
    def test_bucket_create(self, mock_action):
        """Test create command."""
        mock_action.return_value = None

        result = self.runner.invoke(cli.create, [self.bucket.name])

        assert result.exit_code == 0
        assert result.output == 'Bucket %s created\n' % self.bucket.name

        mock_action.assert_called_once_with(
            self.bucket.name, storage=None, transfer=None)

    @mock.patch.object(cli.Client, 'bucket_create')
    def test_bucket_create_with_options(self, mock_action):
        """Test create command."""
        mock_action.return_value = None

        args = [
            '--storage=%u' % self.bucket.storage,
            '--transfer=%u' % self.bucket.transfer,
            self.bucket.name
        ]

        self.logger.debug('test_bucket_create_with_options args=%s', args)
        result = self.runner.invoke(cli.create, args)

        assert result.exit_code == 0
        assert result.output == 'Bucket %s created\n' % self.bucket.name

        mock_action.assert_called_once_with(
            self.bucket.name, storage=self.bucket.storage, transfer=self.bucket.transfer)

    @mock.patch.object(cli.Client, 'bucket_get')
    def test_bucket_get(self, mock_action):
        """Test get command."""
        mock_action.return_value = self.bucket

        result = self.runner.invoke(cli.get, [self.bucket.id])

        assert result.exit_code == 0
        assert result.output == '\n'.join([
            ' created : %s' % self.bucket.created,
            '      id : %s' % self.bucket.id,
            '    name : %s' % self.bucket.name,
            ' pubkeys : %s' % self.bucket.pubkeys,
            '  status : %s' % self.bucket.status,
            ' storage : %u' % self.bucket.storage,
            'transfer : %u' % self.bucket.transfer,
            '    user : %s\n' % self.bucket.user,
        ])

        mock_action.assert_called_once_with(self.bucket.id)

    @mock.patch.object(cli.Client, 'bucket_list')
    def test_bucket_list(self, mock_action):
        """Test list command."""
        mock_action.return_value = [self.bucket]

        result = self.runner.invoke(cli.list, [])

        assert result.exit_code == 0
        assert result.output == '[info]   ID: %s, Name: %s, Storage: %d, Transfer: %d\n' % (
            self.bucket.id, self.bucket.name, self.bucket.storage, self.bucket.transfer)

        mock_action.assert_called_once_with()
