from __future__ import unicode_literals
import collections

from bitforge.encoding import *
from bitforge.errors import *
from bitforge.tools import Buffer
from bitforge.script import Script, PayToPubkeyOut, PayToScriptOut, RedeemMultisig, OpReturnOut


BaseOutput = collections.namedtuple('Output',
    ['amount', 'script']
)


class Output(BaseOutput):

    class Error(BitforgeError):
        pass

    def __new__(cls, amount, script):
        # TODO validation
        return super(Output, cls).__new__(cls, amount, script)

    @classmethod
    def create(cls, amount, script):
        script = Script.create(script.instructions) # classified copy

        if isinstance(script, PayToPubkeyOut):
            return AddressOutput(amount, script)

        elif isinstance(script, PayToScriptOut):
            return ScriptOutput(amount, script)

        elif isinstance(script, OpReturnOut):
            return DataOutput(amount, script)

        else:
            return Output(amount, script)

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

    def to_hex(self):
        return encode_hex(self.to_bytes()).decode('utf-8')

    @staticmethod
    def from_hex(string):
        return Output.from_bytes(decode_hex(string))

    @staticmethod
    def from_bytes(bytes):
        return Output.from_buffer(Buffer(bytes))

    @staticmethod
    def from_buffer(cls, buffer):
        # Inverse operation of Output.to_bytes(), check that out.
        amount = decode_int(buffer.read(8), big_endian = False)

        script_len = buffer.read_varint()
        script = Script.from_bytes(buffer.read(script_len))

        return Output.create(amount, script)


class AddressOutput(Output):

    @classmethod
    def create(cls, amount, address):
        script = PayToPubkeyOut.create(address)
        return cls(amount, script)


class ScriptOutput(Output):

    @classmethod
    def create(cls, amount, redeem_script):
        script = PayToScriptOut.create(redeem_script)
        return cls(amount, script)


class MultisigOutput(ScriptOutput):

    @classmethod
    def create(cls, amount, pubkeys, min_signatures):
        redeem_script = RedeemMultisig.create(pubkeys, min_signatures)
        return cls(amount, redeem_script)


class DataOutput(Output):

    class TooMuchData(Output.Error, NumberError):
        "DataOutputs can carry at most 80 bytes, but {number} were passed in"

    @classmethod
    def create(cls, data):
        if len(data) > 80:
            raise DataOutput.TooMuchData(len(data))

        amount = 0
        script = OpReturnOut.create(data)

        return cls(amount, script)
