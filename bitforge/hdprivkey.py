#!/usr/bin/env python
import os, hmac, hashlib, ecdsa, utils, networks
from privkey import PrivateKey

MIN_SEED_LEN     = 32
HMAC_MAGIC_KEY   = 'Bitcoin seed'
ROOT_FINGERPRINT = '\0\0\0\0'


class HDPrivateKey(object):
    def __init__(self, secret, chain, depth = 0, index = 0, parent = ROOT_FINGERPRINT, network = networks.default):
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

    @staticmethod
    def fromString(b58_str):
        data = utils.encoding.a2b_hashed_base58(b58_str)
        buffers = {
            'version' : data[HDPrivateKey.VersionStart:HDPrivateKey.VersionEnd],
            'depth'   : data[HDPrivateKey.DepthStart:HDPrivateKey.DepthEnd],
            'parent'  : data[HDPrivateKey.ParentFingerPrintStart:HDPrivateKey.ParentFingerPrintEnd],
            'index'   : data[HDPrivateKey.ChildIndexStart:HDPrivateKey.ChildIndexEnd],
            'chain'   : data[HDPrivateKey.ChainCodeStart:HDPrivateKey.ChainCodeEnd],
            'secret'  : data[HDPrivateKey.PrivateKeyStart:HDPrivateKey.PrivateKeyEnd],
            'checksum': data[HDPrivateKey.ChecksumStart:HDPrivateKey.ChecksumEnd],
            'xprivkey': b58_str,
        }
        return buffers

    @staticmethod
    def _fromBuffers(buffers):
        version = utils.intbytes.from_bytes(buff['version'])
        network = networks.find(version, 'xprivkey')


    def toPrivateKey(self):
        ecdsa_key = ecdsa.SigningKey.from_string(self.secret, curve = ecdsa.curves.SECP256k1)
        return PrivateKey(ecdsa_key.privkey.secret_multiplier)

    def __str__(self):
        pass

HDPrivateKey.VersionSize = 4;
HDPrivateKey.DepthSize = 1;
HDPrivateKey.ParentFingerPrintSize = 4;
HDPrivateKey.ChildIndexSize = 4;
HDPrivateKey.ChainCodeSize = 32;
HDPrivateKey.PrivateKeySize = 32;
HDPrivateKey.CheckSumSize = 4;

HDPrivateKey.DataLength = 78;
HDPrivateKey.SerializedByteSize = 82;

HDPrivateKey.VersionStart = 0;
HDPrivateKey.VersionEnd = HDPrivateKey.VersionStart + HDPrivateKey.VersionSize;
HDPrivateKey.DepthStart = HDPrivateKey.VersionEnd;
HDPrivateKey.DepthEnd = HDPrivateKey.DepthStart + HDPrivateKey.DepthSize;
HDPrivateKey.ParentFingerPrintStart = HDPrivateKey.DepthEnd;
HDPrivateKey.ParentFingerPrintEnd = HDPrivateKey.ParentFingerPrintStart + HDPrivateKey.ParentFingerPrintSize;
HDPrivateKey.ChildIndexStart = HDPrivateKey.ParentFingerPrintEnd;
HDPrivateKey.ChildIndexEnd = HDPrivateKey.ChildIndexStart + HDPrivateKey.ChildIndexSize;
HDPrivateKey.ChainCodeStart = HDPrivateKey.ChildIndexEnd;
HDPrivateKey.ChainCodeEnd = HDPrivateKey.ChainCodeStart + HDPrivateKey.ChainCodeSize;
HDPrivateKey.PrivateKeyStart = HDPrivateKey.ChainCodeEnd + 1;
HDPrivateKey.PrivateKeyEnd = HDPrivateKey.PrivateKeyStart + HDPrivateKey.PrivateKeySize;
HDPrivateKey.ChecksumStart = HDPrivateKey.PrivateKeyEnd;
HDPrivateKey.ChecksumEnd = HDPrivateKey.ChecksumStart + HDPrivateKey.CheckSumSize;


# Create randonm privatekey
# Derive
# xpriv -> xpub

buff = HDPrivateKey.fromString('xprv9s21ZrQH143K39tCKhmgNQSCD2hdBstf6rGgdnjU7NeFmTRfEaX1h2PXv9WpXhp8DdMztKdSm6Du89VWyCxRCMcSrgswxSDk1VY49dVnSyR')
version = utils.intbytes.from_bytes(buff['version'])
print networks.find(version, 'xprivkey')
