import error


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
