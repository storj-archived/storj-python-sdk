import os

import click


from six.moves.configparser import RawConfigParser


APP_NAME = 'storj'
"""(str): the application name."""


def read_config():
    """Reads configuration storj client configuration.

    Mac OS X (POSIX):
        ~/.foo-bar
    Unix (POSIX):
        ~/.foo-bar
    Win XP (not roaming):
        ``C:\Documents and Settings\<user>\Application Data\storj``
    Win 7 (not roaming):
        ``C:\\Users\<user>\AppData\Local\storj``

    Returns:
        (dict): configuration.
    """

    # OSX: /Users/<username>/.storj
    cfg = os.path.join(
        click.get_app_dir(
            APP_NAME,
            force_posix=True),
        'storj.ini')

    parser = RawConfigParser()
    parser.read([cfg])

    rv = {}
    for section in parser.sections():
        for key, value in parser.items(section):
            rv['%s.%s' % (section, key)] = value

    return rv
