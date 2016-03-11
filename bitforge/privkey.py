import random, binascii, collections
from . import networks, utils, ecdsa
from .errors import *
from .pubkey import PublicKey
from .address import Address
from .encoding import *


rng     = random.SystemRandom()
KEY_MAX = utils.generator_secp256k1.order()

def random_secret():
    return rng.randint(1, KEY_MAX - 1)


def find_network(value, attr = 'name'):
    try:
        return networks.find(value, attr)
    except networks.UnknownNetwork:
        raise PrivateKey.UnknownNetwork(attr, value)


BasePrivateKey = collections.namedtuple('PrivateKey',
    ['secret', 'network', 'compressed']
)

class PrivateKey(BasePrivateKey):

    class Error(BitforgeError):
        pass

    class InvalidSecret(Error, NumberError):
        "Invalid secret for PrivateKey: {number}"

    class UnknownNetwork(Error, networks.UnknownNetwork):
        "No network for PrivateKey with an attribute '{key}' of value {value}"

    class InvalidWifLength(Error, StringError):
        "The PrivateKey WIF {string} should be 33 (uncompressed) or 34 (compressed) bytes long, not {length}"

    class InvalidCompressionByte(Error, StringError):
        "The length of the PrivateKey WIF {string} suggests it's compressed, but it doesn't end in '\\1'"

    class InvalidBase58h(Error, InvalidBase58h):
        "The PrivateKey string {string} is not valid base58/check"

    class InvalidHex(Error, InvalidHex):
        "The PrivateKey string {string} is not valid hexadecimal"

    class InvalidBinaryLength(Error, StringError):
        "The PrivateKey's binary secret {string} should be 32 bytes long, not {length}"


    def __new__(cls, secret = None, network = networks.default, compressed = True):
        network = find_network(network)

        if secret is None:
            secret = random_secret()

        if not (0 < secret < KEY_MAX):
            raise PrivateKey.InvalidSecret(secret)

        return super(PrivateKey, cls).__new__(cls, secret, network, compressed)

    @staticmethod
    def from_wif(string):
        try:
            bytes = decode_base58h(string)
        except InvalidBase58h:
            raise PrivateKey.InvalidBase58h(string)

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
            raise PrivateKey.InvalidBinaryLength(bytes)

        secret = decode_int(bytes)
        return PrivateKey(secret, network, compressed)

    @staticmethod
    def from_hex(string, network = networks.default, compressed = True):
        try:
            bytes = decode_hex(string)
        except InvalidHex:
            raise PrivateKey.InvalidHex(string)

        return PrivateKey.from_bytes(bytes, network, compressed)

    def to_wif(self):
        network_byte    = chr(self.network.wif_prefix)
        secret_bytes    = self.to_bytes()
        compressed_byte = b'\1' if self.compressed else b''

        return encode_base58h(network_byte + secret_bytes + compressed_byte)

    def to_bytes(self):
        return encode_int(self.secret, length = 32)

    def to_hex(self):
        return encode_hex(self.to_bytes()).decode('utf-8')

    def to_public_key(self):
        return PublicKey.from_private_key(self)

    def to_address(self):
        return Address.from_public_key(self.to_public_key())

    def sign(self, message):
        signing_key = ecdsa.SigningKey.from_secret_exponent(self.secret, curve = ecdsa.SECP256k1)
        return signing_key.sign_digest(message, sigencode = ecdsa.util.sigencode_der_canonize)

    def verify(self, signature, message):
        signing_key   = ecdsa.SigningKey.from_secret_exponent(self.secret, curve = ecdsa.SECP256k1)
        verifying_key = signing_key.get_verifying_key()

        return verifying_key.verify(signature, message, sigdecode = ecdsa.util.sigdecode_der)

    def __repr__(self):
        return "<PrivateKey: %s, network: %s>" % (self.to_hex(), self.network.name)
