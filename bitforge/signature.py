import collections

from bitforge.encoding import *
from bitforge.errors import *
from bitforge.tools import Buffer


BaseSignature = collections.namedtuple('Signature',
    ['', 'script']
)


class Signature(BaseSignature):

    def __new__(cls, amount, script):
        # TODO validation
        return super(Output, cls).__new__(cls, amount, script)

    def to_bytes(self):
        buffer = Buffer()
        script = self.script.to_bytes()

        # Output amount in Satoshis, as little-endian uint64 (8 bytes):
        buffer.write(encode_int(self.amount, length = 8, big_endian = False))

        # Script length, as variable-length integer (1-9 bytes):
        buffer.write(encode_varint(len(script)))

        # Script body (? bytes):
        buffer.write(script)

        return str(buffer)
