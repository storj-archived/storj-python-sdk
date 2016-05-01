# -*- coding: utf-8 -*-

from hashlib import sha256

from ecdsa import SigningKey, SECP256k1

from .api import api_client
from .sdk import BucketManager, UserKeyManager


buckets = BucketManager()
public_keys = UserKeyManager()

authenticate = api_client.authenticate
register_new_user = api_client.register_user


def generate_new_key_pair():

    # Private key
    signing_key = SigningKey.generate(
        curve=SECP256k1,
        hashfunc=sha256,
    )

    # Public key
    verifying_key = signing_key.get_verifying_key()

    return signing_key, verifying_key
