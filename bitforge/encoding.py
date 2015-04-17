import utils, binascii
import error


def encode_base58h(bytes):
    return utils.encoding.b2a_hashed_base58(bytes)


def decode_base58h(string):
    try:
        return utils.encoding.a2b_hashed_base58(string)

    except utils.encoding.EncodingError:
        raise error.InvalidBase58h(string)


def encode_int(integer):
    bytes = bytearray()

    while integer > 0:
        bytes.append(integer & 0xff)
        integer >>= 8

    bytes.reverse()
    return str(bytes)


def decode_int(bytes):
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
        raise error.InvalidHex(string)
