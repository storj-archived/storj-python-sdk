# -*- coding: utf-8 -*-
"""Storj web socket module."""

import json

from ws4py.client.threadedclient import WebSocketClient


class Client(WebSocketClient):
    """Web socket client.

    Attributes:
        json (generator[:py:class:`storj.model.FilePointer`]): file pointers.
    """

    def __init__(self, pointer, file_contents):
        assert isinstance(pointer, dict)

        # according to docs it's channel
        URI = "ws://" + pointer.get('farmer')['address']
        URI += ":" + str(pointer.get('farmer')['port'])
        self.json = pointer
        self.file_contents = file_contents
        super(Client, self).__init__(URI)

    def opened(self):
        self.send(json.dumps(self.json))

    def closed(self, code, reason=None):
        return "Closed web socket %s %s" % (code, reason)

    def received_message(self, m):
        if m.is_binary:
            self.file_contents.write(m.data)
