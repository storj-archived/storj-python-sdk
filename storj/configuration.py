import os

import click


from six.moves import configparser


APP_NAME = 'storj'
"""(str): the application name."""


def read_config():
    """Reads configuration storj client configuration.

    Mac OS X (POSIX):
        ~/.foo-bar
    Unix (POSIX):
        ~/.foo-bar
    Win XP (not roaming):
        C:\Documents and Settings\<user>\Application Data\Foo Bar
    Win 7 (not roaming):
        C:\Users\<user>\AppData\Local\Foo Bar

    Returns:
        (dict): configuration.
    """

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
