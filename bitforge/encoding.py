import binascii
import hashlib

from bitforge import error
from bitforge.utils import encoding


class Error(error.BitforgeError):
    pass


def b2a_hex(data):
    """Convert a byte buffer to an hexadecimal string."""

    return binascii.b2a_hex(data)


def a2b_hex(string):
    """Convert an hexadecimal string to a byte buffer."""

    if len(string) % 2 == 1:
        string = '0' + string

    try:
        return binascii.a2b_hex(string.encode('ascii'))
    except TypeError:
        raise Error('Invalid hexadecimal string')


def b2i_bigendian(data):
    """Convert a big endian byte buffer to an unsigned big integer."""

    # Encoding and decoding from hexa appears to be way faster than manually
    # decoding the buffer in python.
    return int(b2a_hex(data), 16)


def i2b_bigendian(number, num_bytes = 0):
    """Convert an unsigned big integer to a zero-padded big endian byte buffer.
    """

    # Encoding and decoding from hexa appears to be way faster than manually
    # decoding the buffer in python.
    return a2b_hex('%0*x' % (2 * num_bytes, number))


# TODO: implement these functions

def b2a_base58check(data):
    """Convert a byte buffer to a base58check string."""

    return encoding.b2a_hashed_base58(data)


def a2b_base58check(string):
    """Convert a base58check string to a byte buffer."""

    try:
        return encoding.a2b_hashed_base58(string)
    except encoding.EncodingError:
        raise Error('Invalid base58check string')


# TODO: these are not encodings, they shouldn't be here

def sha256(bytes):
    return hashlib.sha256(bytes).digest()


def ripemd160(bytes):
    return hashlib.new('ripemd160', bytes).digest()
