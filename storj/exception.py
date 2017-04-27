# -*- coding: utf-8 -*-
"""Storj exception module."""


class BridgeError(RuntimeError):
    """Storj bridge runtime exception.

    Attributes:
        code (int): error code.
        message (str): error message.
    """

    def __init__(self, code='', message=''):
        super(RuntimeError, self).__init__()

        self.code = code
        self.message = message

    def __str__(self):
        """Returns a string representation of this error.

        Returns:
            str: string representation of this error.
        """
        return '[%s] %s' % (self.code, self.message)


class ClientError(RuntimeError):
    """Storj client runtime exception.

    Attributes:
        message (str): error message.
    """

    def __init__(self, message=''):
        super(RuntimeError, self).__init__()

        self.message = message

    def __str__(self):
        """Returns a string representation of this error.

        Returns:
            str: string representation of this error.
        """
        return self.message


class FarmerError(RuntimeError):
    """Storj farmer runtime exception.

    Attributes:
        code (int): error code.
        message (str): error message.
    """

    def __init__(self, code, message=''):
        super(RuntimeError, self).__init__()

        self.code = code
        self.message = message

    def __str__(self):
        """Returns a string representation of this error.

        Returns:
            str: string representation of this error.
        """
        return '[%s] %s' % (self.code, self.message)


class SuppliedTokenNotAcceptedError(FarmerError):
    """"""

    CODE = 10002

    def __init__(self):
        super(SuppliedTokenNotAcceptedError, self).__init__(
            code=SuppliedTokenNotAcceptedError.CODE)


class HashMismatchError(FarmerError):
    """"""

    CODE = 10003

    def __init__(self):
        super(HashMismatchError, self).__init__(
            code=HashMismatchError.CODE)


StorjBridgeApiError = BridgeError
StorjFarmerError = FarmerError
