#!/usr/bin/env python
import os, hmac, hashlib, collections
import ecdsa, utils, networks
from privkey import PrivateKey
from utils.intbytes import int_from_bytes, int_to_bytes, to_bytes

# TODO: should be in networks.py
# TODO: check which of these are network dependent
MIN_SEED_LEN     = 32
HMAC_MAGIC_KEY   = 'Bitcoin seed'
ROOT_FINGERPRINT = '\0\0\0\0'


BaseHDPrivateKey = collections.namedtuple('HDPrivateKey', 
    ['secret', 'chain', 'depth', 'index', 'parent', 'network']
)

class HDPrivateKey(BaseHDPrivateKey):
    def __new__(cls, secret, chain, depth = 0, index = 0, parent = ROOT_FINGERPRINT, network = networks.default):

        return super(HDPrivateKey, cls).__new__(cls, secret, chain, depth, index, parent, network)

    @staticmethod
    def fromSeed(seed = None):
        if seed is None:
            seed = os.urandom(MIN_SEED_LEN)

        if len(seed) < MIN_SEED_LEN:
            raise ValueError("HDPrivateKey seed must be at least 32 bytes long")

        signed64 = hmac.new(HMAC_MAGIC_KEY, seed, hashlib.sha512).digest()

        return HDPrivateKey(secret = signed64[:32], chain = signed64[32:])

    # TODO: massage this
    @staticmethod
    def from_string(b58_str):
        data = utils.encoding.a2b_hashed_base58(b58_str) # TODO checksum?

        secret = data[HDPrivateKey.PrivateKeyStart : HDPrivateKey.PrivateKeyEnd]
        chain  = data[HDPrivateKey.ChainCodeStart : HDPrivateKey.ChainCodeEnd]
        depth  = int_from_bytes(data[HDPrivateKey.DepthStart : HDPrivateKey.DepthEnd])
        index  = int_from_bytes(data[HDPrivateKey.ChildIndexStart : HDPrivateKey.ChildIndexEnd])
        parent = int_from_bytes(data[HDPrivateKey.ParentFingerPrintStart : HDPrivateKey.ParentFingerPrintEnd])

        # The version field is used to deduce the network:
        version = int_from_bytes(data[HDPrivateKey.VersionStart:HDPrivateKey.VersionEnd])
        network = networks.find(version, 'hd_private_key')

        return HDPrivateKey(secret, chain, depth, index, parent, network)


    def toString(self):
        # just like in the bip: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
        bytes = (""
            + to_bytes(self.network.hd_private_key, length = 4)
            + to_bytes(self.depth, length = 1)
            + to_bytes(self.parent, length = 4)
            + to_bytes(self.index, length = 4)
            + self.chain
            + '\0' # this zero is prepended to the secret for private keys.
                   # HDPublicKey puts no zero. 
            + self.secret
        )

        return utils.encoding.b2a_hashed_base58(bytes)

    def toPrivateKey(self):
        ecdsa_key = ecdsa.SigningKey.from_string(self.secret, curve = ecdsa.curves.SECP256k1)
        return PrivateKey(ecdsa_key.privkey.secret_multiplier)


# with Tebex as tibi:
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

# hdkey = HDPrivateKey.from_string('xprv9s21ZrQH143K39tCKhmgNQSCD2hdBstf6rGgdnjU7NeFmTRfEaX1h2PXv9WpXhp8DdMztKdSm6Du89VWyCxRCMcSrgswxSDk1VY49dVnSyR')
# print hdkey.toString()
