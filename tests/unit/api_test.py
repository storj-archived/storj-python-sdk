# -*- coding: utf-8 -*-

import unittest

from storj import api


class ModuleTestCase(unittest.TestCase):

    def test_ecdsa_to_hex(self):
        key = '\xf8\xd25-\xaf\xa1G\xdb\xa0\xee\xfd\xf9c\x01\xcf\x0cr' \
              '\xcb\xf5\xb6\x1e\xea\xa1FeJ\x0f\x9bv\xc2\xba{\xa83\xdb\\' \
              '\x1a\xb5\x0c\x1a\xd3\xf4\xdb3\xb6.\x95g'

        expected = '04f8d2352dafa147dba0eefdf96301cf0c72cbf5b61eeaa14665' \
                   '4a0f9b76c2ba7ba833db5c1ab50c1ad3f4db33b62e9567'

        self.assertEqual(expected, api.ecdsa_to_hex(key))
