# -*- coding: utf-8 -*-
"""Storj package."""

from ecdsa import SigningKey, SECP256k1
from hashlib import sha256

from .metadata import __version__


def generate_new_key_pair():
    """
    Generate a new key pair.

    Returns:
        tuple(:py:class:`ecdsa.keys.SigningKey`,
              :py:class:`ecdsa.keys.VerifyingKey`):
        key pair (private, public).
    """

    private_key = SigningKey.generate(
        curve=SECP256k1,
        hashfunc=sha256,
    )

    return private_key, private_key.get_verifying_key()
