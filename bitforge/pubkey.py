import binascii, collections
import networks, utils
from address import Address


BasePublicKey = collections.namedtuple('PublicKey',
    ['pair', 'network', 'compressed']
)

class PublicKey(BasePublicKey):
    # TODO: compressed to method???
    # TODO: check arguments
    def __new__(cls, pair, network = networks.default, compressed = True):
        network = networks.find(network)  # may raise UnknownNetwork

        return super(PublicKey, cls).__new__(cls, pair, network, compressed)

    @staticmethod
    def from_private_key(privkey):
        pair = utils.public_pair_for_secret_exponent(
            utils.generator_secp256k1, privkey.secret
        )

        return PublicKey(pair, privkey.network, privkey.compressed)

    @staticmethod
    def from_bytes(bytes, network = networks.default):
        pair       = utils.encoding.sec_to_public_pair(bytes)
        compressed = utils.encoding.is_sec_compressed(bytes)

        return PublicKey(pair, network, compressed)

    @staticmethod
    def from_hex(hex, network = networks.default):
        return PublicKey.from_bytes(binascii.unhexlify(hex), network)

    def to_bytes(self):
        return utils.encoding.public_pair_to_sec(self.pair, self.compressed)

    def to_hex(self):
        return binascii.hexlify(self.to_bytes())

    def to_address(self):
        return Address.from_public_key(self)

    def __repr__(self):
        return "<PublicKey: %s, network: %s>" % (self.to_hex(), self.network.name)
