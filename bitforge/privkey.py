import collections

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec

from bitforge import encoding, error, network, pubkey, tools


class Error(error.BitforgeError):
    pass


class InvalidExponent(Error):
    """Invalid private key secret exponent"""


class InvalidEncoding(Error):
    pass


BasePrivateKey = collections.namedtuple('PrivateKey', [
    'key',  # Elliptic curve private key
    'network',  # Bitcoin-compatible network
    'compressed',  # Whether the public key should be serialized in compressed format
])


class PrivateKey(BasePrivateKey):
    """Bitcoin private key."""

    def __new__(cls, key, network=network.default, compressed=True):
        """Create a Bitcoin private key from an EC private key."""

        return super(PrivateKey, cls).__new__(cls, key, network, compressed)

    @classmethod
    def generate(cls, network=network.default, compressed=True, backend=default_backend()):
        """Generate a new private key."""

        key = ec.generate_private_key(network.curve, backend)

        return cls(key, network, compressed)

    @classmethod
    def from_secret_exponent(cls, exponent, network=network.default, compressed=True, backend=default_backend()):
        """Create a private key from its secret exponent.

        The secret exponent should be an unsigned integer (d), strictly between
        0 and the elliptic curve order (n). Bitcoin's curve order is:

        n = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141
        """

        # NOTE: This implementation is only temporary. Whenever cryptography
        # implements the from_private_number_and_curve method, change what
        # follows to:
        #
        #   try:
        #       private_numbers = ec.EllipticCurvePrivateNumbers.from_private_value_and_curve(exponent, network.curve, backend)
        #   except ??:
        #       raise InvalidExponent()
        #
        #   key = private_numbers.private_key(backend)

        import hashlib
        import ecdsa
        from cryptography.hazmat.primitives.serialization import load_der_private_key

        try:
            sig_key = ecdsa.SigningKey.from_secret_exponent(exponent, curve=ecdsa.curves.SECP256k1, hashfunc=hashlib.sha256)
        except AssertionError:
            raise InvalidExponent()

        key = load_der_private_key(sig_key.to_der(), password=None, backend=backend)

        return cls(key, network, compressed)

    @classmethod
    def from_bytes(cls, data, network=network.default, compressed=True, backend=default_backend()):
        """Create a private key from its raw binary encoding (in SEC1 format).

        The input buffer should be a zero-padded big endian unsigned integer.
        For more info on this format, see:

        http://www.secg.org/sec1-v2.pdf, section 2.3.6
        """

        if len(data) != tools.elliptic_curve_key_size(network.curve):
            raise InvalidEncoding('Invalid key length')

        exponent = encoding.b2i_bigendian(data)

        try:
            return cls.from_secret_exponent(exponent, network, compressed, backend)

        except InvalidExponent as e:
            raise InvalidEncoding(e.message)

    @classmethod
    def from_wif(cls, wif, backend=default_backend()):
        """Create a private key from its WIF encoding.

        The Wallet Import Format encoding is used for serializing Bitcoin
        private keys. For more info on this encoding, see:

        https://en.bitcoin.it/wiki/Wallet_import_format
        """

        # A WIF private key is base58check encoded
        try:
            data = bytearray(encoding.a2b_base58check(wif))

        except encoding.Error as e:
            raise InvalidEncoding(e.message)

        # The first byte determines the network
        try:
            prefix = data.pop(0)

        except IndexError:
            raise InvalidEncoding('Invalid WIF length')

        try:
            network_ = network.Network.get_by_field('wif_prefix', prefix)

        except network.UnknownNetwork as e:
            raise InvalidEncoding(e.message)

        # If the public key should be compressed-encoded, there will be an
        # extra 1 byte at the end
        key_size = tools.elliptic_curve_key_size(network_.curve)

        compressed = True if len(data) == key_size + 1 else False

        if compressed and data[-1] == 1:
            data.pop(-1)

        # What remains should be the raw private key exponent
        return cls.from_bytes(bytes(data), network_, compressed, backend)

    def public_key(self):
        """The PublicKey object for this private key."""

        return pubkey.PublicKey(self.key.public_key(), self.network, self.compressed)

    def sign(self, message):
        """TODO"""

        signer = self.key.signer(ec.ECDSA(self.network.hash_function))
        signer.update(message)

        der_sig = signer.finalize()
        return der_sig

    def to_bytes(self):
        """TODO"""

        key_size = tools.elliptic_curve_key_size(self.network.curve)

        exponent = self.key.private_numbers().private_value

        return encoding.i2b_bigendian(exponent, key_size)

    def to_wif(self):
        """TODO"""

        data = bytearray()

        data.append(self.network.wif_prefix)
        data.extend(self.to_bytes())

        if self.compressed:
            data.append(1)

        return encoding.b2a_base58check(bytes(data))

    def __repr__(self):
        return "<PrivateKey network: {} compressed: {}>".format(str(self.network), self.compressed)
