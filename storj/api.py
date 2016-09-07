# -*- coding: utf-8 -*-
"""Storj API module."""

from binascii import b2a_hex


def ecdsa_to_hex(ecdsa_key):
    """
    Return hexadecimal string representation of the ECDSA key.

    Args:
        ecdsa_key (bytes): ECDSA key.

    Raises:
        TypeError: if the ECDSA key is not an array of bytes.

    Returns:
        str: hexadecimal string representation of the ECDSA key.
    """
    return '04%s' % b2a_hex(ecdsa_key).decode('ascii')
