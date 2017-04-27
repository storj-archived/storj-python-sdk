# -*- coding: utf-8 -*-
"""Test cases for the storj.exception module."""

from .. import AbstractTestCase

from storj.exception import \
    BridgeError, \
    ClientError, \
    FarmerError, \
    HashMismatchError, \
    SuppliedTokenNotAcceptedError


class BridgeErrorTestCase(AbstractTestCase):
    """Test case for the BridgeError."""

    @staticmethod
    def assertBridgeError(error, code, message):
        """Assert BridgeError expected conditions.

        Args:
            error (:py:class:`storj.exception.BridgeError`): result.
            code (int): expected error code.
            message (str): expected error message.
        """

        assert code == error.code
        assert message == error.message
        assert '[%d] %s' % (code, message) == str(error)

    def test(self):
        expected_code = 0
        expected_message = 'error'
        error = BridgeError(expected_code, expected_message)

        self.assertBridgeError(error, expected_code, expected_message)


class ClientErrorTestCase(AbstractTestCase):
    """Test case for the ClientError."""

    @staticmethod
    def assertClientError(error, message):
        """Assert ClientError expected conditions.

        Args:
            error (:py:class:`storj.exception.BridgeError`): result.
            message (str): expected error message.
        """

        assert message == error.message
        assert message == str(error)

    def test(self):
        expected = 'error'
        error = ClientError(expected)

        self.assertClientError(error, expected)


class FarmerErrorTestCase(AbstractTestCase):
    """Test case for the FarmerError."""

    @staticmethod
    def assertFarmerError(error, code, message):
        """Assert FarmerError expected conditions.

        Args:
            error (:py:class:`storj.exception.FarmerError`): result.
            code (int): expected error code.
            message (str): expected error message.
        """

        assert code == error.code
        assert message == error.message
        assert '[%d] %s' % (code, message) == str(error)

    def test(self):
        expected_code = 0
        expected_message = 'error'
        error = FarmerError(expected_code, expected_message)

        self.assertFarmerError(error, expected_code, expected_message)


class HashMismatchErrorErrorTestCase(FarmerErrorTestCase):
    """Test case for the HashMismatchError."""

    def test(self):
        expected = ''
        error = HashMismatchError()

        self.assertFarmerError(error, HashMismatchError.CODE, expected)


class SuppliedTokenNotAcceptedErrorTestCase(FarmerErrorTestCase):
    """Test case for the SuppliedTokenNotAcceptedError."""

    def test(self):
        expected = ''
        error = SuppliedTokenNotAcceptedError()

        self.assertFarmerError(
            error, SuppliedTokenNotAcceptedError.CODE, expected)
