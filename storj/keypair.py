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

    """

    def __init__(self, pkey=None, secret=None):
        """
        Represents a ECDSA key pair
        """
        self.keypair = None

        if pkey:
            self.keypair = Key(secret_exponent=int(pkey, 16))

        if secret:
            self.__from_master_secret(secret)

        if not pkey and not secret:
            self.__from_random()

    def __from_master_secret(self, secret):
        # generate a Wallet from a master password
        self.keypair = BIP32Node.from_master_secret(secret)

    def __from_random(self):
        try:
            self.keypair = BIP32Node.from_master_secret(urandom(4096))
        except NotImplementedError:
            print("No randomness source is not found: ", sys.exc_info()[0])
            raise

    def get_node_id(self):
        """
        Returns the NodeID derived from the public key.

        Returns:
            (str): RIPEMD160 hash of public key.
        """
        return b2h(self.keypair.hash160())

    def get_public_key(self):
        """
        Returns the public key.

        Returns:
            (str): public key.
        """
        return b2h(self.keypair.sec(use_uncompressed=False))

    def get_private_key(self):
        """
        Returns the private key.

        Returns:
            (str): private key.
        """
        return format(self.keypair.secret_exponent(), "064x")

    def get_address(self):
        """
        Returns the bitcoin address version of the nodeID.

        Returns:
            (): Base58 encoded address
        """
        return self.keypair.address(use_uncompressed=False)

    # TODO: add sign function
