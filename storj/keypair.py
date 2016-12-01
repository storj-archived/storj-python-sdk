# -*- coding: utf-8 -*-
"""Storj KeyPair module."""

from __future__ import print_function
from pycoin.key.Key import Key
from pycoin.serialize import b2h
from pycoin.key.BIP32Node import BIP32Node
from os import urandom
import sys


class KeyPair(object):

    def __init__(self, pkey=None, secret=None):
        """
        Represents a ECDSA key pair
        :param pkey: generate a Keypair from existing private key
        :param secret: generate a Keypair from self choosen secret
        """
        self.keypair = None

        if secret:
            self.__from_master_secret(secret)

        if pkey:
            self.keypair = Key(secret_exponent=int(pkey, 16))

        if not pkey and not secret:
            self.__from_random()

    def __from_master_secret(self, secret):
        pkey = format(BIP32Node.from_master_secret(secret).secret_exponent(), "064x")
        self.keypair = Key(secret_exponent=int(pkey, 16))

    def __from_random(self):
        try:
            pkey = format(BIP32Node.from_master_secret(urandom(4096)).secret_exponent(), "064x")
            self.keypair = Key(secret_exponent=int(pkey, 16))
        except NotImplementedError:
            print("No randomness source is not found: ", sys.exc_info()[0])
            raise

    def get_node_id(self):
        """
        Returns the NodeID derived from the public key
        :return: nodeID - RIPEMD160 hash of public key
        """
        return b2h(self.keypair.hash160())

    def get_public_key(self):
        """
        Returns the public key
        :return: key
        """
        return b2h(self.keypair.sec(use_uncompressed=False))

    def get_private_key(self):
        """
        Returns the private key
        :return: key
        """
        return format(self.keypair.secret_exponent(), "064x")

    def get_address(self):
        """
        Returns the bitcoin address version of the nodeID
        :return: address - Base58 encoded address
        """
        return self.keypair.address(use_uncompressed=False)

    # TODO: add sign function
