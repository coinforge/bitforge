#!/usr/bin/env python
import os, hmac, hashlib, ecdsa
from privkey import PrivateKey

MIN_SEED_LEN     = 32
HMAC_MAGIC_KEY   = 'Bitcoin seed'
ROOT_FINGERPRINT = '\0\0\0\0'


class HDPrivateKey(object):
    def __init__(self, secret, chain, depth = 0, index = 0, parent = ROOT_FINGERPRINT):
        self.secret = secret
        self.chain  = chain
        self.depth  = depth
        self.index  = index
        self.parent = parent

    @staticmethod
    def fromSeed(seed = None):
        if seed is None:
            seed = os.urandom(MIN_SEED_LEN)

        if len(seed) < MIN_SEED_LEN:
            raise ValueError("HDPrivateKey seed must be at least 32 bytes long")

        signed64 = hmac.new(HMAC_MAGIC_KEY, seed, hashlib.sha512).digest()

        return HDPrivateKey(secret = signed64[:32], chain = signed64[32:])

    def toPrivateKey(self):
        ecdsa_key = ecdsa.SigningKey.from_string(self.secret, curve = ecdsa.curves.SECP256k1)
        return PrivateKey(ecdsa_key.privkey.secret_multiplier)
