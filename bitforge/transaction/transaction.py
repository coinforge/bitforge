import collections

from bitforge.encoding import *
from bitforge.errors import *
from bitforge.tools import Buffer
from bitforge.script import Script


BaseTransaction = collections.namedtuple('Transaction',
    ['inputs', 'outputs', 'lock_time', 'version']
)


class Transaction(BaseTransaction):

    def __new__(cls, inputs, outputs, lock_time = 0, version = 1):
        # TODO validation
        inputs  = list(inputs)
        outputs = list(outputs)

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

    def get_raw_id(self):
        return sha256(sha256(self.to_bytes()))

    def get_id(self):
        return encode_hex(self.get_raw_id())

    def with_inputs(self, inputs):
        return Transaction(inputs, self.outputs, self.lock_time, self.version)

    def signed(self, txi_index, privkey):
        # To sign a Transaction Input with a PrivateKey, we need to:

        # 1. Create a simplified version of the Transaction, where this Input
        # script is set to the previous Transaction's matching Output script,
        # and all other Input scripts are empty (0 bytes).

        # 2. Double SHA256 this reduced Transaction, and sign that data with the
        # provided PrivateKey. This is the actual signature.

        # 3. Build a new Transaction, restoring the other Input scripts, and
        # setting this Input script to the version including the signature.

        simplified_inputs = (
            i if index == txi_index else i.with_script('')
            for index, i in enumerate(self.inputs)
        )

        simplified_transaction = self.with_inputs(simplified_inputs)

        signature = privkey.sign(simplified_transaction.get_raw_id())

        signed_input_script = Script.pay_to_address_in(
            privkey.to_public_key(),
            signature
        )

        new_inputs = (
            i.with_script(signed_input_script) if index == txi_index else i
            for index, i in enumerate(self.inputs)
        )

        return self.with_inputs(new_inputs)
