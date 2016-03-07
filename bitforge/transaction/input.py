import collections

from bitforge.encoding import *
from bitforge.errors import *
from bitforge.tools import Buffer
from bitforge.signature import SIGHASH_ALL
from bitforge import Script


FINAL_SEQ_NUMBER = 0xFFFFFFFF


BaseInput = collections.namedtuple('Input',
    ['tx_id', 'txo_index', 'script', 'seq_number']
)


class Input(BaseInput):

    class Error(BitforgeError):
        pass

    class UnknownSignatureMethod(Error):
        "This abstract Input doesn't know how to sign itself. You should use an Input subclass, such as AddressInput"

    class InvalidSignatureCount(Error):
        "This Input requires {required} keys to sign, but {provided} were provided"

        def prepare(self, required_keys, provided_keys):
            self.required = required_keys
            self.provided = provided_keys


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

    def with_script(self, script):
        return Input(self.tx_id, self.txo_index, script, self.seq_number)

    def signed(self, privkeys, payload):
        raise UnknownSignatureMethod()


class AddressInput(Input):

    def __new__(cls, tx_id, txo_index, address, seq_number = FINAL_SEQ_NUMBER):
        placeholder_script = Script.pay_to_pubkey_out(address)
        return super(AddressInput, cls).__new__(cls, tx_id, txo_index, placeholder_script, seq_number)

    def signed(self, privkeys, payload):
        if len(privkeys) != 1:
            raise AddressInput.InvalidSignatureCount(1, len(privkeys))

        signed_script = Script.pay_to_pubkey_in(
            pubkey    = privkeys[0].to_public_key(),
            signature = privkeys[0].sign(payload) + chr(SIGHASH_ALL)
        )

        return self.with_script(signed_script)


class ScriptInput(Input):

    def signed(self, privkeys, payload):
        signed_script = Script.pay_to_script_in(
            script     = self.script,
            signatures = [ pk.sign(payload) + chr(SIGHASH_ALL) for pk in privkeys ]
        )

        return self.with_script(signed_script)


class MultisigInput(ScriptInput):

    def __new__(cls, tx_id, txo_index, pubkeys, min_signatures, seq_number = FINAL_SEQ_NUMBER):
        placeholder_script = Script.redeem_multisig(pubkeys, min_signatures)
        return super(MultisigInput, cls).__new__(cls, tx_id, txo_index, placeholder_script, seq_number)
