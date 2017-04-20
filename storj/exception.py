# -*- coding: utf-8 -*-
"""Storj exception module."""


class StorjBridgeApiError(Exception):
    """Generic Storj exception."""
    pass


class StorjFarmerError(Exception):
    """Storj Farmer Exception"""
    SUPPLIED_TOKEN_NOT_ACCEPTED = 10002
    CALCULATED_HASH_NOT_MATCH_EXPECTED_RESULT = 10003
    pass
