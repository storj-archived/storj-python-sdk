# -*- coding: utf-8 -*-
"""Storj command-line interface package."""

import logging

import click


from .. import get_client


__logger = logging.getLogger(__name__)


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
@click.option('--storage', default=None, help='Storage limit', type=click.INT)
@click.option('--transfer', default=None,
              help='Transfer limit', type=click.INT)
@click.argument('name', type=click.STRING)
def create(storage, transfer, name):
    """Create bucket.

    Args:
        storage (int): storage limit (in GB).
        transfer (int): transfer limit (in GB).
        name (str): bucket name.
    """
    get_client().bucket_create(name, storage=storage, transfer=transfer)
    click.echo('Bucket %s created' % name)


@bucket.command()
@click.argument('bucket_id', type=click.STRING)
def get(bucket_id):
    """Get bucket."""
    bucket = get_client().bucket_get(bucket_id)

    for attr, value in sorted(bucket.__dict__.items()):
        click.echo('%s : %s' % (attr.rjust(18), value))


@bucket.command()
def list():
    """List buckets."""
    for bucket in get_client().bucket_list():
        click.echo(
            '[info]   ID: %s, Name: %s, Storage: %d, Transfer: %d' % (
                bucket.id, bucket.name, bucket.storage, bucket.transfer)
        )


@click.group()
def file():
    pass


@file.command()
@click.argument('bucket_id', type=click.STRING)
@click.argument('file_path', type=click.File('r'))
def upload(bucket_id, file_path):
    """Upload file to a storage bucket."""
    get_client().file_upload(bucket_id, file_path)
