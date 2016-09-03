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
def list():
    """List buckets."""
    for bucket in get_client().get_buckets():
        click.echo(bucket)
