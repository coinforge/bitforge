#!/usr/bin/env python
import os, hmac, hashlib, collections
import ecdsa, utils, network
from network import Network
from privkey import PrivateKey
from hdpubkey import HDPublicKey
from utils.intbytes import int_from_bytes, int_to_bytes, to_bytes

# TODO: should be in networks.py
# TODO: check which of these are network dependent
MIN_SEED_LEN     = 32
HMAC_MAGIC_KEY   = 'Bitcoin seed'
ROOT_FINGERPRINT = 0
HARDENED_START   = 0x80000000


def calculate_fingerprint(privkey):
    return utils.encoding.hash160(privkey.to_public_key().to_bytes())[:4]


BaseHDPrivateKey = collections.namedtuple('HDPrivateKey',
    ['privkey', 'chain', 'depth', 'index', 'parent', 'network', 'fingerprint']
)

class HDPrivateKey(BaseHDPrivateKey):
    def __new__(cls, privkey, chain, depth = 0, index = 0, parent = ROOT_FINGERPRINT, network = network.default):
        assert isinstance(privkey, PrivateKey)
        fingerprint = int_from_bytes(calculate_fingerprint(privkey))

        return super(HDPrivateKey, cls).__new__(cls, privkey, chain, depth, index, parent, network, fingerprint)

    @staticmethod
    def fromSeed(seed = None):
        if seed is None:
            seed = os.urandom(MIN_SEED_LEN)

        if len(seed) < MIN_SEED_LEN:
            raise ValueError("HDPrivateKey seed must be at least 32 bytes long")

        signed64 = hmac.new(HMAC_MAGIC_KEY, seed, hashlib.sha512).digest()

        return HDPrivateKey(privkey = PrivateKey.from_bytes(signed64[:32]), chain = signed64[32:])

    # TODO: massage this
    @staticmethod
    def from_string(b58_str):
        data = utils.encoding.a2b_hashed_base58(b58_str) # TODO checksum?

        chain   = data[HDPrivateKey.ChainCodeStart : HDPrivateKey.ChainCodeEnd]
        depth   = int_from_bytes(data[HDPrivateKey.DepthStart : HDPrivateKey.DepthEnd])
        index   = int_from_bytes(data[HDPrivateKey.ChildIndexStart : HDPrivateKey.ChildIndexEnd])
        parent  = int_from_bytes(data[HDPrivateKey.ParentFingerPrintStart : HDPrivateKey.ParentFingerPrintEnd])

        # The version field is used to deduce the network:
        version = int_from_bytes(data[HDPrivateKey.VersionStart:HDPrivateKey.VersionEnd])
        network = Network.get_by_field('hd_private_key', version)
        privkey = PrivateKey.from_bytes(data[HDPrivateKey.PrivateKeyStart : HDPrivateKey.PrivateKeyEnd], network)

        return HDPrivateKey(privkey, chain, depth, index, parent, network)


    def to_string(self):
        # See BIP 32: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
        bytes = (""
            + to_bytes(self.network.hd_private_key, length = 4)
            + to_bytes(self.depth, length = 1)
            + to_bytes(self.parent, length = 4)
            + to_bytes(self.index, length = 4)
            + self.chain
            + '\0' # this zero is prepended to private keys. HDPublicKey doesn't do it
            + self.to_private_key().to_bytes()
        )

        return utils.encoding.b2a_hashed_base58(bytes)


    def derive(self, index, hardened = False):
        # TODO Is index Valid?

        if index < HARDENED_START and hardened:
            index += HARDENED_START

        if hardened:
            key = '\0' + self.to_private_key().to_bytes() # a literal 0 is prepended to private keys
        else:
            key = self.to_public_key().to_bytes()

        signed64 = hmac.new(
            self.chain,
            key + to_bytes(self.index, length = 4),
            hashlib.sha512
        ).digest()

        seed    = (int_from_bytes(signed64[:32]) + self.to_private_key().seed) % utils.generator_secp256k1.order()
        privkey = PrivateKey(seed, self.network)
        chain   = signed64[32:]
        depth   = self.depth + 1

        return HDPrivateKey(privkey, chain, depth, index, self.fingerprint, self.network)

    def to_hd_public_key(self):
        return HDPublicKey.from_hd_private_key(self)

    def to_private_key(self):
        return self.privkey

    def to_public_key(self):
        return self.to_private_key().to_public_key()


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
