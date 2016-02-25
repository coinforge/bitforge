import collections

from bitforge.encoding import *
from bitforge.errors import *
from bitforge.tools import Buffer


BaseTransaction = collections.namedtuple('Transaction',
    ['inputs', 'outputs', 'lock_time', 'version']
)


class Transaction(BaseTransaction):

    def __new__(cls, inputs, outputs, lock_time = 0, version = 1):
        # TODO validation
        return super(Input, cls).__new__(cls, inputs, outputs, lock_time, version)

    def to_bytes(self):
        # Version number, as little-endian uint32 (4 bytes):
        buffer.write(encode_int(self.version, length = 4, big_endian = False))

        # Number of inputs, as variable-length integer (1-9 bytes):
        buffer.write(encode_varint(len(self.inputs)))

        # Serialized inputs (? bytes):
        for input in self.inputs: buffer.write(input.to_bytes())

        # Number of outputs, as variable-length integer (1-9 bytes):
        buffer.write(encode_varint(len(self.outputs)))

        # Serialized outputs (? bytes):
        for output in self.outputs: buffer.write(output.to_bytes())

        # Transaction lock time, as little-endian uint32 (4 bytes):
        buffer.write(encode_int(self.lock_time))
