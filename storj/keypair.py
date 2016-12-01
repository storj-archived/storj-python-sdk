# -*- coding: utf-8 -*-
"""Storj KeyPair module."""

import sys

from os import urandom

from pycoin.key.Key import Key
from pycoin.serialize import b2h
from pycoin.key.BIP32Node import BIP32Node


class KeyPair(object):
    """
    ECDSA key pair.

    Args:
        pkey (str): hexadecimal representation of the private key (secret exponent).
        secret (str): master password.

    Attributes:
        keypair (:py:class:`pycoin.key.Key.Key`): BIP0032-style hierarchical wallet.
    """

    def __init__(self, pkey=None, secret=None):

        if pkey is not None:
            self.keypair = Key(secret_exponent=int(pkey, 16))

        elif secret:
            # generate a wallet from a master password
            self.keypair = BIP32Node.from_master_secret(secret)

        else:
            try:
                # generate a wallet from a random password
                self.keypair = BIP32Node.from_master_secret(urandom(4096))
            except NotImplementedError:
                raise ValueError('No randomness source found: ', sys.exc_info()[0])

    @property
    def node_id(self):
        """(str): NodeID derived from the public key (RIPEMD160 hash of public key)."""
        return b2h(self.keypair.hash160())

    @property
    def public_key(self):
        """(str): public key."""
        return b2h(self.keypair.sec(use_uncompressed=False))

    @property
    def private_key(self):
        """(str): private key."""
        return format(self.keypair.secret_exponent(), "064x")

    @property
    def address(self):
        """(): base58 encoded bitcoin address version of the nodeID."""
        return self.keypair.address(use_uncompressed=False)
