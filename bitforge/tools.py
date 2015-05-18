import ecdsa
from cryptography.hazmat.primitives.asymmetric import ec

from bitforge import error


class Buffer(bytearray):

    class Error(error.BitforgeError):
        pass

    class InsufficientData(Error):
        "Attempted to read {requested} bytes, but buffer only has {remaining}"

        def prepare(self, remaining, requested):
            self.remaining = remaining
            self.requested = requested

    def read(self, amount):
        if len(self) < amount:
            raise Buffer.InsufficientData(len(self), amount)

        ret = str(self[:amount])
        del self[:amount]
        return ret

    def write(self, data):
        self.extend(data)


def elliptic_curve_key_size(curve):
    """Size (in bytes) of an elliptic curve private key."""

    return (curve.key_size + 7) // 8


# TODO: this is a temporary hack. Ideally, it should be implemented by
# cryptography.
def ec_public_y_from_x_and_curve(x, y_parity, curve):
    """Compute the y coordinate of a point in an elliptic curve.

    For more info, see:

        http://www.secg.org/sec1-v2.pdf, section 2.3.4, step 2.4.1
    """

    assert isinstance(curve, ec.SECP256K1)
    curve = ecdsa.SECP256k1.curve

    # The curve equation over F_p is:
    #   y^2 = x^3 + ax + b
    a, b, p = curve.a(), curve.b(), curve.p()

    alpha = (pow(x, 3, p) + a * x + b) % p

    try:
        beta = ecdsa.numbertheory.square_root_mod_prime(alpha, p)
    except ecdsa.numbertheory.SquareRootError:
        return None

    beta_parity = beta % 2

    if beta_parity != y_parity:
        beta = p - beta

    return beta
