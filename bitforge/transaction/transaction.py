import collections

from bitforge.encoding import *
from bitforge.errors import *
from bitforge.tools import Buffer
from bitforge.script import Script


#
SIGHASH_ALL = 0x01


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
        # A transaction is signed in 4 steps:
        #   1. Create a reduced Transaction without data from other Inputs
        #   2. Sign the reduced Transaction, discard it, keep the signature
        #   3. Create the signed Input Script for the actual Transaction
        #   4. Build the actual transaction, restoring data from other Inputs

        # Let's go step by step.

        # 1. Create a simplified version of the Transaction, where this Input
        # script is set to the previous Transaction's matching Output script,
        # and all other Input scripts are empty (0 bytes).

        simplified_inputs = (
            i if index == txi_index else i.with_script('')
            for index, i in enumerate(self.inputs)
        )

        simplified_transaction = self.with_inputs(simplified_inputs)

        # 2. Write the payload we're going to sign, which is the serialization
        # of the simplified transaction, with an extra 4 bytes for the signature
        # type, all of that double-sha256'd:

        payload = simplified_transaction.to_bytes()
        payload += encode_int(SIGHASH_ALL, length = 4, big_endian = False)
        payload = sha256(sha256(payload))

        # 3. Build the signed Script for the Input, bundling in the public key
        # and the signature with the appended type (1 byte this time):

        signed_input_script = Script.pay_to_address_in(
            pubkey    = privkey.to_public_key(),
            signature = privkey.sign(payload) + chr(SIGHASH_ALL)
        )

        # 4. Build a new Transaction, restoring the other Input scripts, and
        # setting this Input script to the new version including the signature:
        new_inputs = (
            i.with_script(signed_input_script) if index == txi_index else i
            for index, i in enumerate(self.inputs)
        )

        return self.with_inputs(new_inputs)


    def signed_multisig(self, txi_index, privkeys, redeem_script):
        simplified_inputs = (
            i.with_script(redeem_script) if index == txi_index else i.with_script('')
            for index, i in enumerate(self.inputs)
        )

        simplified_transaction = self.with_inputs(simplified_inputs)

        payload = simplified_transaction.to_bytes()
        payload += encode_int(SIGHASH_ALL, length = 4, big_endian = False)
        payload = sha256(sha256(payload))

        signatures = [
            privkey.sign(payload) + chr(SIGHASH_ALL)
            for privkey in privkeys
        ]

        from bitforge.signature import validate_signature
        if not all(map(validate_signature, signatures)):
            raise Exception(signatures)

        signed_input_script = Script.pay_to_script_in(
            script     = redeem_script,
            signatures = signatures
        )

        # print ''
        # print 'SIGNED IN SCRIPT', signed_input_script
        # print ''
        # print signed_input_script.to_string()
        # print ''
        # print ''

        new_inputs = (
            i.with_script(signed_input_script) if index == txi_index else i
            for index, i in enumerate(self.inputs)
        )

        return self.with_inputs(new_inputs)
