import binascii, collections
from enum import Enum

from . import networks, utils
from .encoding import *
from .errors import *
from .compat import chr
# from script import Script


BaseAddress = collections.namedtuple('Address', ['phash', 'network', 'type'])

class Address(BaseAddress):

    class Type(Enum):
        PublicKey = 'pubkeyhash'
        Script    = 'scripthash'

    class Error(BitforgeError):
        pass

    class UnknownNetwork(Error, networks.UnknownNetwork):
        "No network for Address with an attribute '{key}' of value {value}"

    class InvalidVersion(Error, NumberError):
        "Failed to detect Address type and network from version number {number}"

    class InvalidBase58h(Error, InvalidBase58h):
        "The Address string {string} is not valid base58/check"

    class InvalidHex(Error, InvalidHex):
        "The Address string {string} is not valid hexadecimal"

    class InvalidHashLength(Error, StringError):
        "The address hash {string} should be 20 bytes long, not {length}"

    class InvalidBinaryLength(Error, StringError):
        "The binary address {string} should be 21 bytes long, not {length}"

    class InvalidType(Error, ObjectError):
        "Address type {object} is not an instance of Address.Type"


    def __new__(cls, phash, network = networks.default, type = Type.PublicKey):
        try   : network = networks.find(network)
        except: raise Address.UnknownNetwork('name', network)

        if not isinstance(type, Address.Type):
            raise Address.InvalidType(type)

        if len(phash) != 20:
            raise Address.InvalidHashLength(phash)

        return super(Address, cls).__new__(cls, phash, network, type)

    @staticmethod
    def from_string(string):
        try:
            bytes = decode_base58h(string)
        except InvalidBase58h:
            raise Address.InvalidBase58h(string)

        return Address.from_bytes(bytes)

    @staticmethod
    def from_bytes(bytes):
        if len(bytes) != 21:
            raise Address.InvalidBinaryLength(bytes)

        network, type = Address.classify_bytes(bytes)

        return Address(bytes[1:], network, type)

    @staticmethod
    def from_hex(string):
        try:
            bytes = decode_hex(string)
        except InvalidHex:
            raise Address.InvalidHex(string)

        return Address.from_bytes(bytes)

    @staticmethod
    def classify_bytes(bytes):
        version = bytearray(bytes)[0]

        network = networks.find(version, 'pubkeyhash', raises = False)
        if network is not None:
            return (network, Address.Type.PublicKey)

        network = networks.find(version, 'scripthash', raises = False)
        if network is not None:
            return (network, Address.Type.Script)

        raise Address.InvalidVersion(version)

    @staticmethod
    def from_public_key(pubkey):
        phash = ripemd160(sha256(pubkey.to_bytes()))
        return Address(phash, pubkey.network, Address.Type.PublicKey)

    @staticmethod
    def from_script(script, network = networks.default):
        phash = ripemd160(sha256(script.to_bytes()))
        return Address(phash, network, Address.Type.Script)

    def to_bytes(self):
        version = getattr(self.network, self.type.value)
        return chr(version) + self.phash

    def to_string(self):
        return encode_base58h(self.to_bytes())

    def to_hex(self):
        return encode_hex(self.to_bytes()).decode('utf-8')

    # TODO: all keys should be from the same network
    # @staticmethod
    # def from_public_keys(pubkeys, threshold):
    #     return Address.from_script(
    #         Script.buildMultisigOut(pubkeys, threshold),
    #         pubkeys[0].network
    #     )

    # @staticmethod
    # def from_script(script, network = networks.default):
    #     if not isinstance(script, Script):
    #         raise ValueError('Expected instance of Script, not %s' % script)
    #
    #     return Address(
    #         raw     = utils.encoding.hash160(script.to_bytes()),
    #         type    = Address.Type.Script,
    #         network = network
    #     )

    def __repr__(self):
        return "<Address: %s, type: %s, network: %s>" % (self.to_string(), self.type.name, self.network.name)
