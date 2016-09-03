# -*- coding: utf-8 -*-
"""Storj command-line interface package."""

import click

from storj.api import generate_new_key_pair, export_keys, import_keys


@click.group
def cli():
    pass


@click.command
def generate_keys():
    pass


@click.command
def export_keys():
    pass


@click.command
def import_keys():
    pass
