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


def encode_int(integer, big_endian = True, length = None):
    bytes = bytearray()

    while integer > 0:
        bytes.append(integer & 0xff)
        integer >>= 8

    if length is not None:
        zeros = chr(0) * length # TODO if number can't fit in length, raise
        bytes = (bytes + zeros)[:length]

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


def encode_varint(integer):
    # TODO check integer is a postive number
    if integer < 253:
        return encode_int(integer)

    elif integer <= 0xFFFF:
        return chr(253) + encode_int(integer, length = 2, big_endian = False)

    elif integer <= 0xFFFFFFFF:
        return chr(254) + encode_int(integer, length = 4, big_endian = False)

    else:
        return chr(255) + encode_int(integer, length = 8, big_endian = False)

  # if (n < 253) {
  #   buf = new Buffer(1);
  #   buf.writeUInt8(n, 0);
  # } else if (n < 0x10000) {
  #   buf = new Buffer(1 + 2);
  #   buf.writeUInt8(253, 0);
  #   buf.writeUInt16LE(n, 1);
  # } else if (n < 0x100000000) {
  #   buf = new Buffer(1 + 4);
  #   buf.writeUInt8(254, 0);
  #   buf.writeUInt32LE(n, 1);
  # } else {
  #   buf = new Buffer(1 + 8);
  #   buf.writeUInt8(255, 0);
  #   buf.writeInt32LE(n & -1, 1);
  #   buf.writeUInt32LE(Math.floor(n / 0x100000000), 5);
  # }


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
