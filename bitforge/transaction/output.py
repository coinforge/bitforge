import collections

from bitforge.encoding import *
from bitforge.errors import *
from bitforge.tools import Buffer
from bitforge import Script


BaseOutput = collections.namedtuple('Output',
    ['amount', 'script']
)


class Output(BaseOutput):

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


class AddressOutput(Output):

    def __new__(cls, amount, address):
        script = Script.pay_to_pubkey_out(address)
        return super(AddressOutput, cls).__new__(cls, amount, script)


class ScriptOutput(Output):

    def __new__(cls, amount, redeem_script):
        script = Script.pay_to_script_out(redeem_script)
        return super(ScriptOutput, cls).__new__(cls, amount, script)


class MultisigOutput(ScriptOutput):

    def __new__(cls, amount, pubkeys, min_signatures):
        redeem_script = Script.redeem_multisig(pubkeys, min_signatures)
        return super(MultisigOutput, cls).__new__(cls, amount, redeem_script)
