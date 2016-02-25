import collections

from bitforge.encoding import *
from bitforge.errors import *
from bitforge.tools import Buffer


FINAL_SEQ_NUMBER = 4294967295


BaseInput = collections.namedtuple('Input',
    ['tx_id', 'txo_index', 'script', 'seq_number']
)


class Input(BaseInput):

    def __new__(cls, tx_id, txo_index, script, seq_number = FINAL_SEQ_NUMBER):
        # TODO validation
        return super(Input, cls).__new__(cls, tx_id, txo_index, script, seq_number)

    def to_bytes(self):
        buffer = Buffer()
        script = self.script.to_bytes()

        # Reverse transaction ID (double SHA256 hex of previous tx) (32 bytes):
        buffer.write(reversed(decode_hex(self.tx_id)))

        # Previous tx output index, as little-endian uint32 (4 bytes):
        buffer.write(encode_int(self.txo_index, length = 4, big_endian = False))

        # Script length, as variable-length integer (1-9 bytes):
        buffer.write(encode_varint(len(script)))

        # Script body (? bytes):
        buffer.write(script)

        # Sequence number, as little-endian uint32 (4 bytes):
        buffer.write(encode_int(self.seq_number, length = 4, big_endian = False))

        return str(buffer)
