import random, struct, binascii, collections
import networks, utils
from pubkey import PublicKey
from address import Address


rng     = random.SystemRandom()
KEY_MAX = utils.generator_secp256k1.order()

def random_seed():
    return rng.randint(1, KEY_MAX - 1)


# TODO: compress in methods instead of constructor???
BasePrivateKey = collections.namedtuple('PrivateKey',
    ['seed', 'network', 'compressed']
)

class PrivateKey(BasePrivateKey):
    def __new__(cls, seed = None, network = networks.default, compressed = True):
        network = networks.find(network)

        if seed is None:
            seed = random_seed()

        return super(PrivateKey, cls).__new__(cls, seed, network, compressed)

    @staticmethod
    def from_wif(wif):
        data    = utils.encoding.a2b_hashed_base58(wif)
        network = networks.find(ord(data[0]), 'wif_prefix')

        compressed = len(data) > 33
        if compressed:
            data = data[:-1]

        seed = utils.encoding.from_bytes_32(data[1:])

        return PrivateKey(seed, network, compressed)

    def to_wif(self):
        bytes = chr(self.network.wif_prefix) + self.to_bytes()

        if self.compressed:
            bytes += '\1'

        return utils.encoding.b2a_hashed_base58(bytes)

    # TODO: add converse factories from_bytes, from_hex
    def to_bytes(self):
        return utils.encoding.to_bytes_32(self.seed)

    def to_hex(self):
        return binascii.hexlify(self.to_bytes())

    def to_public_key(self):
        return PublicKey.from_private_key(self)

    def to_address(self):
        return Address.from_public_key(self.to_public_key())

    def __repr__(self):
        return "<PrivateKey: %s, network: %s>" % (self.to_hex(), self.network.name)
