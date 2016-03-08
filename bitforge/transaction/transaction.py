import collections

from bitforge.encoding import *
from bitforge.errors import *
from bitforge.tools import Buffer, enforce_all, instance_of
from bitforge.signature import SIGHASH_ALL
from bitforge.script import Script
from bitforge.transaction import Input, Output


BaseTransaction = collections.namedtuple('Transaction',
    ['inputs', 'outputs', 'lock_time', 'version']
)


class Transaction(BaseTransaction):

    class Error(BitforgeError):
        pass

    class NoInputs(Error):
        "No Inputs were given to create this Transaction"

    class NoOutputs(Error):
        "No Outputs were given to create this Transaction"

    class NotAnInput(Error, ObjectError):
        "Transaction expected instances of Input, got {object} instead"

    class NotAnOutput(Error, ObjectError):
        "Transaction expected instances of Input, got {object} instead"

    class InvalidLockTime(Error, NumberError):
        "Transaction lock_time must be between 0 and 4294967295 (2^32 - 1), not {number}"


    def __new__(cls, inputs, outputs, lock_time = 0, version = 1):
        inputs = tuple(inputs)
        outputs = tuple(outputs)

        if len(inputs) == 0: raise cls.NoInputs()
        enforce_all(inputs, instance_of(Input), cls.NotAnInput)

        if len(outputs) == 0: raise cls.NoOutputs()
        enforce_all(outputs, instance_of(Output), cls.NotAnOutput)

        if not (0 <= lock_time <= 0xFFFFFFFF):
            raise cls.InvalidLockTime(lock_time)

        return super(Transaction, cls).__new__(cls, inputs, outputs, lock_time, version)

    def to_bytes(self):
        buffer = Buffer()

        # Version number, as little-endian uint32 (4 bytes):
        buffer.write(encode_int(self.version, length = 4, big_endian = False))

        # Number of inputs, as variable-length integer (1-9 bytes):
        buffer.write(encode_varint(len(self.inputs)))

        # Serialized inputs (? bytes):
        for input in self.inputs:
            buffer.write(input.to_bytes())

        # Number of outputs, as variable-length integer (1-9 bytes):
        buffer.write(encode_varint(len(self.outputs)))

        # Serialized outputs (? bytes):
        for output in self.outputs:
            buffer.write(output.to_bytes())

        # Transaction lock time, as little-endian uint32 (4 bytes):
        buffer.write(encode_int(self.lock_time, length = 4, big_endian = False))

        return str(buffer)

    def to_hex(self):
        return encode_hex(self.to_bytes())

    def get_id_bytes(self):
        return sha256(sha256(self.to_bytes()))

    def get_id(self):
        return encode_hex(self.get_id_bytes())

    def with_inputs(self, inputs):
        return Transaction(inputs, self.outputs, self.lock_time, self.version)

    def signed(self, privkeys, txi_index):
        # A Transaction Input is signed in 4 steps:
        #   1. Create a simplified Transaction without data from other Inputs
        #   2. Sign the simplified Transaction data, discard it, keep the signature
        #   3. Create a new Input including the signature
        #   4. Build the signed Transaction, restoring data from other Inputs

        # Let's go step by step.

        # 1. Create a simplified version of the Transaction, where this Input
        # Script is a placeholder (the signature can't sign itself), and all
        # other Input scripts are empty (0 bytes). The placeholder should be
        # there already, manually placed or auto-created by Input subclasses.

        simplified_inputs = (
            input.without_script() if i != txi_index else input
            for i, input in enumerate(self.inputs)
        )

        simplified_transaction = self.with_inputs(simplified_inputs)

        # 2. Write the payload we're going to sign, which is the serialization
        # of the simplified transaction, with an extra 4 bytes for the signature
        # type, all of that double-sha256'd:

        payload = simplified_transaction.to_bytes()
        payload += encode_int(SIGHASH_ALL, length = 4, big_endian = False)
        payload = sha256(sha256(payload))

        # 3. Create the signed Input, making it sign itself using the provided
        # PrivateKeys. Each Input subclass knows how to handle this process. The
        # signed Input will loose the placeholder Script and get a real one.

        signed_input = self.inputs[txi_index].signed(privkeys, payload)

        # 4. Build a new Transaction, restoring the other Input Scripts, and
        # setting this Input to the new version including the signature:

        new_inputs = (
            signed_input if i == txi_index else input
            for i, input in enumerate(self.inputs)
        )

        return self.with_inputs(new_inputs) # voila!


    @staticmethod
    def from_bytes(bytes):
        buffer = Buffer(bytes)

        version = decode_int(buffer.read(4), big_endian = False)

        ninputs = buffer.read_varint()
        inputs  = [ Input.from_buffer(buffer) for i in range(ninputs) ]

        noutputs = buffer.read_varint()
        outputs  = [ Output.from_buffer(buffer) for i in range(noutputs) ]

        lock_time = decode_int(buffer.read(4), big_endian = False)

        return Transaction(inputs, outputs, lock_time, version)

    @staticmethod
    def from_hex(hex):
        return Transaction.from_bytes(decode_hex(hex))
