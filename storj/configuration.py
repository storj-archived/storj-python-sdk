import os

import click


from six.moves import configparser


APP_NAME = 'storj'


def read_config():
    """Reads configuration for the command-line interface."""

    # OSX: /Users/<username>/.storj
    cfg = os.path.join(
        click.get_app_dir(
            APP_NAME,
            force_posix=True),
        'storj.ini')

    parser = configparser.RawConfigParser()
    parser.read([cfg])

    rv = {}
    for section in parser.sections():
        for key, value in parser.items(section):
            rv['%s.%s' % (section, key)] = value

    return rv
