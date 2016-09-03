# -*- coding: utf-8 -*-
"""Storj API module."""

import json

from binascii import b2a_hex

try:
    from json.decoder import JSONDecodeError
except ImportError:
    # Python 2
    JSONDecodeError = ValueError

try:
    from urllib.parse import urljoin, urlencode
except ImportError:
    # Python 2
    from urllib import urlencode
    from urlparse import urljoin

from ws4py.client.threadedclient import WebSocketClient


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


class MetadiskApiError(Exception):
    pass


class FileRetrieverWebSocketClient(WebSocketClient):

    def __init__(self, pointer, file_contents):
        assert isinstance(pointer, dict)
        URI = "ws://" + pointer.get('farmer')['address'] + ":" + str(pointer.get('farmer')['port'])
        self.json = pointer
        self.file_contents = file_contents
        super(FileRetrieverWebSocketClient, self).__init__(URI)

    def opened(self):
        self.send(json.dumps(self.json))

    def closed(self, code, reason=None):
        return "Closed web socket %s %s" % (code, reason)

    def received_message(self, m):
        if m.is_binary:
            self.file_contents.write(m.data)
