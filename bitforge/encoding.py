import utils, binascii, hashlib
from errors import StringError


class EncodingError(StringError):
    "The string {string} is not properly encoded"


class InvalidBase58h(EncodingError):
    "The string {string} is not valid base58/check"


class InvalidHex(EncodingError):
    "The string {string} is not valid hexadecimal"


def encode_base58h(bytes):
    return utils.encoding.b2a_hashed_base58(bytes)


def decode_base58h(string):
    try:
        return utils.encoding.a2b_hashed_base58(string)

    except utils.encoding.EncodingError:
        raise InvalidBase58h(string)


def encode_int(integer, big_endian = True):
    bytes = bytearray()

    while integer > 0:
        bytes.append(integer & 0xff)
        integer >>= 8

    if big_endian:
        bytes.reverse()

    return str(bytes)


def decode_int(bytes, big_endian = True):
    if not big_endian:
        bytes = reversed(bytes)

    integer = 0

    for char in bytes:
        integer <<= 8
        integer += ord(char)

    return integer


def encode_hex(bytes):
    return binascii.hexlify(bytes)


def decode_hex(string):
    try:
        return binascii.unhexlify(string)
    except:
        # unhexlify() throws 2 different exceptions (length, and alphabet)
        raise InvalidHex(string)


def sha256(bytes):
    return hashlib.sha256(bytes).digest()


def ripemd160(bytes):
    return hashlib.new('ripemd160', bytes).digest()
