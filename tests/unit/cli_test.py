# -*- coding: utf-8 -*-
"""Test cases for the storj.cli package."""

import mock

from datetime import datetime

from click.testing import CliRunner

from storj import cli, http, model

from .. import AbstractTestCase


class FunctionsTestCase(AbstractTestCase):
    """Test case for the package functions."""

    @mock.patch.object(http.Client, '__init__')
    @mock.patch('storj.cli.read_config', autospec=True)
    def test_get_client(self, mock_read_config, mock_init):
        mock_read_config.return_value = {
            cli.CFG_EMAIL: 'someone@example.com',
            cli.CFG_PASSWORD: 'secret'
        }

        assert cli.get_client() is not None

        mock_read_config.assert_called_once_with()
        mock_init.assert_called_once_with('someone@example.com', 'secret')

    @mock.patch.object(cli.ConfigParser, 'RawConfigParser')
    def test_read_config(self, mock_parser):
        mock_parser.sections.return_value = {
            'storj': {
                'email': 'someone@example.com',
                'password': 'secret'
            }}

        assert cli.read_config() == {
            cli.CFG_EMAIL: 'someone@example.com',
            cli.CFG_PASSWORD: 'secret'
        }

        mock_parser.sections.assert_called_once_with()


class BucketTestCase(AbstractTestCase):
    """Test case for bucket commands."""

    runner = CliRunner()

    def setUp(self):
        self.test_id = 'unit-%s' % datetime.utcnow().strftime('%Y%m%d_%H%M%S')

        self.bucket = model.Bucket(
            id=self.test_id, name='bucket', storage=100, transfer=100)

    @mock.patch.object(cli.Client, 'bucket_create')
    def test_bucket_create(self, mock_action):
        """Test create command."""
        result = self.runner.invoke(cli.create, [self.test_id])

        assert result.exit_code == 0
        assert result.output == 'Hello Peter!\n'

        mock_action.assert_called_once_with()

    @mock.patch.object(cli.Client, 'bucket_get')
    def test_bucket_get(self, mock_action):
        """Test get command."""
        mock_action.return_value = self.bucket

        result = self.runner.invoke(cli.get, [self.test_id])

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
