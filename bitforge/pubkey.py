import collections

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from bitforge import address, encoding, error, network, tools


# Magic numbers for the SEC1 public key format (TODO: shouldn't be here!)
SEC1_MAGIC_COMPRESSED_0 = 2
SEC1_MAGIC_COMPRESSED_1 = 3
SEC1_MAGIC_NOT_COMPRESSED = 4


class Error(error.BitforgeError):
    pass


class InvalidPoint(Error):
    """Invalid key (the point represented by the key is not on the curve)"""


class InvalidEncoding(Error):
    pass


BasePublicKey = collections.namedtuple('PublicKey', [
    'key',  # Elliptic curve public key
    'network',  # Bitcoin-compatible network
    'compressed',  # Whether the key should be serialized in compressed format
])


class PublicKey(BasePublicKey):
    """Bitcoin public key."""

    def __new__(cls, key, network=network.default, compressed=True):
        """Create a Bitcoin public key from an EC public key."""

        return super(PublicKey, cls).__new__(cls, key, network, compressed)

    @classmethod
    def from_point(cls, x, y, network=network.default, compressed=True, backend=default_backend()):
        """Create a public key from its point coordinates.

        A public key is a point on an elliptic curve, i.e. a pair (x, y) that
        satisfies the curve equation.
        """

        public_numbers = ec.EllipticCurvePublicNumbers(x, y, network.curve)

        try:
            key = public_numbers.public_key(backend)
        except ValueError:
            raise InvalidPoint()

        return cls(key, network, compressed)

    @classmethod
    def from_bytes(cls, data, network=network.default, backend=default_backend()):
        """Create a public key from its raw binary encoding (in SEC1 format).

        For more info on this format, see:

        http://www.secg.org/sec1-v2.pdf, section 2.3.4
        """

        data = bytearray(data)

        # A public key is a point (x, y) in the elliptic curve, and each
        # coordinate is represented by a unsigned integer of key_size bytes
        key_size = tools.elliptic_curve_key_size(network.curve)

        # The first byte determines whether the key is compressed
        try:
            prefix = data.pop(0)

        except IndexError:
            raise InvalidEncoding('Invalid key length (buffer is empty)')

        # If the key is compressed-encoded, only the x coordinate is present
        compressed = True if len(data) == key_size else False

        if not compressed and len(data) != 2 * key_size:
            raise InvalidEncoding('Invalid key length')

        # The first key_size bytes after the prefix are the x coordinate
        x = encoding.b2i_bigendian(bytes(data[:key_size]))

        if compressed:
            # If the key is compressed, the y coordinate should be computed

            if prefix == SEC1_MAGIC_COMPRESSED_0:
                y_parity = 0
            elif prefix == SEC1_MAGIC_COMPRESSED_1:
                y_parity = 1
            else:
                raise InvalidEncoding('Invalid prefix for compressed key')

            y = tools.ec_public_y_from_x_and_curve(x, y_parity, network.curve)
            if y is None:
                raise InvalidPoint()
        else:
            # If the key isn't compressed, the last key_size bytes are the y
            # coordinate

            if prefix != SEC1_MAGIC_NOT_COMPRESSED:
                raise InvalidEncoding('Invalid prefix for non-compressed key')

            y = encoding.b2i_bigendian(bytes(data[key_size:]))

        return cls.from_point(x, y, network, compressed, backend)

    def address(self, backend=default_backend()):
        """TODO"""

        SHA256 = hashes.Hash(hashes.SHA256(), backend)
        SHA256.update(self.to_bytes())

        RIPEMD160 = hashes.Hash(hashes.RIPEMD160, backend)
        RIPEMD160.update(SHA256.finalize())

        digest = RIPEMD160.finalize()

        return address.Address(digest, self.network, address.Type.PublicKey)

    def to_bytes(self):
        """TODO"""

        public_numbers = self.key.public_numbers()
        key_size = tools.elliptic_curve_key_size(self.network.curve)

        prefix = SEC1_MAGIC_NOT_COMPRESSED

        if self.compressed:
            if public_numbers.y % 2 == 0:
                prefix = SEC1_MAGIC_COMPRESSED_0
            else:
                prefix = SEC1_MAGIC_COMPRESSED_1

        data = bytearray()
        data.append(prefix)

        x = encoding.i2b_bigendian(public_numbers.x, key_size)
        data.extend(x)

        if not self.compressed:
            y = encoding.i2b_bigendian(public_numbers.y, key_size)
            data.extend(y)

        return bytes(data)

    def __repr__(self):
        return "<PublicKey: %s, network: %s>" % (self.to_hex(), self.network.name)
