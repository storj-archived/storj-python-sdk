import unittest
import storj
from ecdsa.keys import SigningKey, VerifyingKey


class TestGenerateNewKeyPair(unittest.TestCase):

    def test_generate_new_key_pair(self):
        private_key, public_key = storj.generate_new_key_pair()
        self.assertIsInstance(private_key, SigningKey)
        self.assertIsInstance(public_key, VerifyingKey)


if __name__ == "__main__":
    unittest.main()
