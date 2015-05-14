#!/usr/bin/env python
import os, hmac, hashlib, collections
import ecdsa, utils, network
from network import Network
from pubkey import PublicKey
from utils.intbytes import int_from_bytes, int_to_bytes, to_bytes


ROOT_FINGERPRINT = 0
HARDENED_START   = 0x80000000


def calculate_fingerprint(pubkey):
    return utils.encoding.hash160(pubkey.to_bytes())[:4]

BaseHDPublicKey = collections.namedtuple('HDPublicKey',
    ['pubkey', 'chain', 'depth', 'index', 'parent', 'network', 'fingerprint']
)

class HDPublicKey(BaseHDPublicKey):
    def __new__(cls, pubkey, chain, depth = 0, index = 0, parent = ROOT_FINGERPRINT, network = network.default):
        assert isinstance(pubkey, PublicKey)
        fingerprint = int_from_bytes(calculate_fingerprint(pubkey))

        return super(HDPublicKey, cls).__new__(cls, pubkey, chain, depth, index, parent, network, fingerprint)

    @staticmethod
    def fromSeed(seed = None):
        if seed is None:
            seed = os.urandom(MIN_SEED_LEN)

        if len(seed) < MIN_SEED_LEN:
            raise ValueError("HDPublicKey seed must be at least 32 bytes long")

        signed64 = hmac.new(HMAC_MAGIC_KEY, seed, hashlib.sha512).digest()

        return HDPublicKey(pubkey = PublicKey.from_bytes(signed64[:32]), chain = signed64[32:])

    # TODO: massage this
    @staticmethod
    def from_string(b58_str):
        data = utils.encoding.a2b_hashed_base58(b58_str) # TODO checksum?

        chain   = data[HDPublicKey.ChainCodeStart : HDPublicKey.ChainCodeEnd]
        depth   = int_from_bytes(data[HDPublicKey.DepthStart : HDPublicKey.DepthEnd])
        index   = int_from_bytes(data[HDPublicKey.ChildIndexStart : HDPublicKey.ChildIndexEnd])
        parent  = int_from_bytes(data[HDPublicKey.ParentFingerPrintStart : HDPublicKey.ParentFingerPrintEnd])

        # The version field is used to deduce the network:
        version = int_from_bytes(data[HDPublicKey.VersionStart:HDPublicKey.VersionEnd])
        network = Network.get_by_field('hd_public_key', version)
        pubkey  = PublicKey.from_bytes(data[HDPublicKey.PublicKeyStart : HDPublicKey.PublicKeyEnd], network)

        return HDPublicKey(pubkey, chain, depth, index, parent, network)

    # TODO: should this belong to hdprivatekey?
    @staticmethod
    def from_hd_private_key(hd_private_key):
        pubkey = hd_private_key.privkey.to_public_key()
        return HDPublicKey(pubkey, hd_private_key.chain, hd_private_key.depth,
                           hd_private_key.index, hd_private_key.parent, hd_private_key.network)

    def to_string(self):
        # See BIP 32: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
        bytes = (""
            + to_bytes(self.network.hd_public_key, length = 4)
            + to_bytes(self.depth, length = 1)
            + to_bytes(self.parent, length = 4)
            + to_bytes(self.index, length = 4)
            + self.chain
            + self.to_public_key().to_bytes()
        )

        return utils.encoding.b2a_hashed_base58(bytes)


    def derive(self, index, hardened = False):
        # TODO Is index Valid?

        if index < HARDENED_START and hardened:
            index += HARDENED_START

        if hardened:
            raise ValueError("Hardened derivation is not posible on HDPublicKey")
        else:
            key = self.to_public_key().to_bytes()

        signed64 = hmac.new(
            self.chain,
            key + to_bytes(self.index, length = 4),
            hashlib.sha512
        ).digest()

        x, y = self.pubkey.pair
        curve = utils.generator_secp256k1
        point = int_from_bytes(signed64[:32]) * curve + utils.Point(curve.curve(), x, y, curve.order())
        pubkey = PublicKey((point.x(), point.y()), self.network)

        chain   = signed64[32:]
        depth   = self.depth + 1

        return HDPublicKey(pubkey, chain, depth, index, self.fingerprint, self.network)

    def to_public_key(self):
        return self.pubkey


HDPublicKey.VersionSize = 4;
HDPublicKey.DepthSize = 1;
HDPublicKey.ParentFingerPrintSize = 4;
HDPublicKey.ChildIndexSize = 4;
HDPublicKey.ChainCodeSize = 32;
HDPublicKey.PublicKeySize = 33;
HDPublicKey.CheckSumSize = 4;

HDPublicKey.DataSize = 78;
HDPublicKey.SerializedByteSize = 82;

HDPublicKey.VersionStart           = 0;
HDPublicKey.VersionEnd             = HDPublicKey.VersionStart + HDPublicKey.VersionSize;
HDPublicKey.DepthStart             = HDPublicKey.VersionEnd;
HDPublicKey.DepthEnd               = HDPublicKey.DepthStart + HDPublicKey.DepthSize;
HDPublicKey.ParentFingerPrintStart = HDPublicKey.DepthEnd;
HDPublicKey.ParentFingerPrintEnd   = HDPublicKey.ParentFingerPrintStart + HDPublicKey.ParentFingerPrintSize;
HDPublicKey.ChildIndexStart        = HDPublicKey.ParentFingerPrintEnd;
HDPublicKey.ChildIndexEnd          = HDPublicKey.ChildIndexStart + HDPublicKey.ChildIndexSize;
HDPublicKey.ChainCodeStart         = HDPublicKey.ChildIndexEnd;
HDPublicKey.ChainCodeEnd           = HDPublicKey.ChainCodeStart + HDPublicKey.ChainCodeSize;
HDPublicKey.PublicKeyStart         = HDPublicKey.ChainCodeEnd;
HDPublicKey.PublicKeyEnd           = HDPublicKey.PublicKeyStart + HDPublicKey.PublicKeySize;
HDPublicKey.ChecksumStart          = HDPublicKey.PublicKeyEnd;
HDPublicKey.ChecksumEnd            = HDPublicKey.ChecksumStart + HDPublicKey.CheckSumSize;
