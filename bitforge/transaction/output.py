import collections

from bitforge.encoding import *
from bitforge.errors import *
from bitforge.tools import Buffer
from bitforge.script import Script


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

    @classmethod
    def from_hex(cls, string):
        return cls.from_bytes(decode_hex(string))

    @classmethod
    def from_bytes(cls, bytes):
        return cls.from_buffer(Buffer(bytes))

    @classmethod
    def from_buffer(cls, buffer):
        # Inverse operation of Output.to_bytes(), check that out.
        amount = decode_int(buffer.read(8), big_endian = False)

        script_len = buffer.read_varint()
        script     = Script.from_bytes(buffer.read(script_len))

        return cls(amount, script)


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


class DataOutput(Output):

    class Error(BitforgeError):
        pass

    class TooMuchData(Error, NumberError):
        "DataOutputs can carry at most 80 bytes, but {number} were passed in"


    def __new__(cls, bytes):
        if len(bytes) > 80:
            raise DataOutput.TooMuchData(len(bytes))

        amount = 0
        script = Script.op_return(bytes)

        return super(DataOutput, cls).__new__(cls, amount, script)
