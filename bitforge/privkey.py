import random, struct, binascii, collections
import networks, utils
from errors import *
from pubkey import PublicKey
from address import Address
from encoding import *


rng     = random.SystemRandom()
KEY_MAX = utils.generator_secp256k1.order()

def random_secret():
    return rng.randint(1, KEY_MAX - 1)


BasePrivateKey = collections.namedtuple('PrivateKey',
    ['secret', 'network', 'compressed']
)


def find_network(value, attr = 'name'):
    return networks.find(value, attr, PrivateKey.UnknownNetwork)


class PrivateKey(BasePrivateKey):
    class Error(BitforgeError):
        pass

    class InvalidSecret(Error, NumberError):
        "Invalid secret for PrivateKey: {number}"

    class InvalidWifLength(Error, StringError):
        "The WIF {string} should be 33 (uncompressed) or 34 (compressed) bytes long, not {length}"

    class InvalidSecretLength(Error, StringError):
        "The secret {string} should be 32 bytes long, not {length}"

    class InvalidCompressionByte(Error, StringError):
        "The length of the WIF {string} suggests it's compressed, but it doesn't end in '\1'"

    class UnknownNetwork(Error, networks.UnknownNetwork):
        "No network for PrivateKey with an attribute '{key}' of value {value}"


    def __new__(cls, secret = None, network = networks.default, compressed = True):
        network = find_network(network)

        if secret is None:
            secret = random_secret()

        if not (0 < secret < KEY_MAX):
            raise PrivateKey.InvalidSecret(secret)

        return super(PrivateKey, cls).__new__(cls, secret, network, compressed)

    @staticmethod
    def from_wif(string):
        bytes = decode_base58h(string)

        if len(bytes) == 33:
            compressed = False

        elif len(bytes) == 34:
            if bytes[-1] != '\1':
                raise PrivateKey.InvalidCompressionByte(string)

            bytes = bytes[:-1]
            compressed = True

        else:
            raise PrivateKey.InvalidWifLength(bytes)

        network = find_network(ord(bytes[0]), 'wif_prefix')
        secret  = decode_int(bytes[1:])

        return PrivateKey(secret, network, compressed)

    @staticmethod
    def from_bytes(bytes, network = networks.default, compressed = True):
        if len(bytes) != 32:
            raise PrivateKey.InvalidSecretLength(bytes)

        secret = decode_int(bytes)
        return PrivateKey(secret, network, compressed)

    @staticmethod
    def from_hex(string, network = networks.default, compressed = True):
        bytes = decode_hex(string)
        return PrivateKey.from_bytes(bytes, network, compressed)

    def to_wif(self):
        network_byte    = chr(self.network.wif_prefix)
        secret_bytes    = self.to_bytes()
        compressed_byte = '\1' if self.compressed else ''

        return encode_base58h(network_byte + secret_bytes + compressed_byte)

    def to_bytes(self):
        return encode_int(self.secret)

    def to_hex(self):
        return encode_hex(self.to_bytes())

    def to_public_key(self):
        return PublicKey.from_private_key(self)

    def to_address(self):
        return Address.from_public_key(self.to_public_key())

    def __repr__(self):
        return "<PrivateKey: %s, network: %s>" % (self.to_hex(), self.network.name)
