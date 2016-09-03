# -*- coding: utf-8 -*-
"""Storj command-line interface package."""

import os
import click
import ConfigParser

# from storj.api import generate_new_key_pair, export_key, import_key
from storj.http import Client


APP_NAME = 'storj'

CFG_EMAIL = 'storj.email'
CFG_PASSWORD = 'storj.password'


def get_client():
    """Returns a pre-configured Storj HTTP client.

    Returns:
        (:py:class:`Client`): Storj HTTP client.
    """
    cfg = read_config()
    return Client(cfg[CFG_EMAIL], cfg[CFG_PASSWORD])


def read_config():
    """Reads configuration for the command-line interface."""

    # OSX: /Users/<username>/Library/Application Support/storj
    cfg = os.path.join(click.get_app_dir(APP_NAME), 'storj.ini')

    parser = ConfigParser.RawConfigParser()
    parser.read([cfg])

    rv = {}
    for section in parser.sections():
        for key, value in parser.items(section):
            rv['%s.%s' % (section, key)] = value

    return rv


@click.group()
def key():
    pass


@key.command()
def generate():
    client = get_client()


@key.command
def export():
    pass


@key.command
def load():
    pass


@click.group()
def bucket():
    pass


@bucket.command()
@click.option('--storage', default=None, help='Storage limit.', type=click.INT)
@click.option('--transfer', default=None, help='Transfer limit', type=click.INT)
@click.argument('name', type=click.STRING)
def create(storage, transfer, name):
    """Create bucket.

    Args:
        storage (int): storage limit (in ??).
        transfer (int): transfer limit (in ??).
        name (str): bucket name.
    """
    get_client().create_bucket(name, storage_limit=storage, transfer_limit=transfer)
    click.echo('Bucket %s created' % name)


@bucket.command()
@click.argument('bucket_id', type=click.STRING)
def get(bucket_id):
    """Get bucket."""
    bucket = get_client().get_bucket(bucket_id)

    for attr, value in bucket.__dict__.iteritems():
        click.echo('%s : %s' % (attr.rjust(8), value))


@bucket.command()
@click.option('--full', default=False, is_flag=True)
def list(full):
    """List buckets."""
    for bucket in get_client().get_buckets():
        if full:
            click.echo(repr(bucket))
        else:
            click.echo(bucket.name)
