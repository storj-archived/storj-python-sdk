# -*- coding: utf-8 -*-

import os
import jsonschema
from storj import http
from micropayment_core import keys
from . import Integration


USER_REGISTER_RESULT = {
    "type": "object",
    "properties": {
        "pubkey": {"type": "string"},
        "activated": {"type": "boolean"},
        "id": {"type": "string"},
        "created": {"type": "string"},
        "email": {"type": "string"}
    },
    "additionalProperties": False,
    "required": ["pubkey", "activated", "id", "created", "email"]
}


CONTACTS_LIST_SCHEMA = {
    "type": "array",
    "itmes": {
        "type": {
            "type": "object",
            "properties": {
                "address": "string",
                "port": "integer",
                "nodeID": "string",
                "lastSeen": "string",
                "userAgent": "string",
                "protocol": "string"
            },
            "additionalProperties": False,
            "required": ["address", "port", "nodeID", "lastSeen", "protocol"]
        }
    }
}


USER_ACTIVATE_RESULT = {
    "type": "object",
    "properties": {
        "activated": {"type": "boolean"},
        "created": {"type": "string"},
        "email": {"type": "string"}
    },
    "additionalProperties": False,
    "required": ["activated", "created", "email"]
}


class UsersIntegrationTestCase(Integration):

    def test(self):
        super(UsersIntegrationTestCase, self).setUp()

        # FIXME move to integration
        client = http.Client(
            email="{0}@bar.com".format(keys.b2h(os.urandom(32))),
            password="12345",
            privkey=keys.generate_privkey(),
            # url="http://api.staging.storj.io/"
        )

        # test call
        apispec = client.call(method="GET")
        self.assertEqual(apispec["info"]["title"], u"Storj Bridge")

        # contacts list
        result = client.contacts_list()
        jsonschema.validate(result, CONTACTS_LIST_SCHEMA)

        # register user
        result = client.user_register()
        jsonschema.validate(result, USER_REGISTER_RESULT)

        self.assertFalse(True)
        # FIXME test activate user
        # result = client.user_activate("TODO get token")
        # jsonschema.validate(result, USER_ACTIVATE_RESULT)
