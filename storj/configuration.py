import os

import click


from six.moves.configparser import RawConfigParser


APP_NAME = 'storj'
"""(str): the application name."""

CFG_EMAIL = 'email'
"""(str): configuration parameter that holds the Storj account email address."""
CFG_PASSWORD = 'password'
"""(str): configuration parameter that holds the Storj account password."""


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
        (tuple[str, str]): storj account credentials (email, password).
    """

    # OSX: /Users/<username>/.storj
    cfg = os.path.join(
        click.get_app_dir(
            APP_NAME,
            force_posix=True),
        'storj.ini')

    parser = RawConfigParser()
    parser.read([cfg])

    return parser.get(APP_NAME, CFG_EMAIL), parser.get(APP_NAME, CFG_PASSWORD)
