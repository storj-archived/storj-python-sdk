# -*- coding: utf-8 -*-
"""Storj package."""

from hashlib import sha256

from ecdsa import SigningKey, SECP256k1

from .api import api_client
from .metadata import __version__
from .sdk import BucketManager, UserKeyManager


buckets = BucketManager()
public_keys = UserKeyManager()

authenticate = api_client.authenticate
register_new_user = api_client.register_user


def generate_new_key_pair():
    """
    Generate a new key pair.

    Returns:
        tuple(:py:class:`ecdsa.keys.SigningKey`, :py:class:`ecdsa.keys.VerifyingKey`):
        key pair (private, public).
    """

    private_key = SigningKey.generate(
        curve=SECP256k1,
        hashfunc=sha256,
    )

    return private_key, private_key.get_verifying_key()
