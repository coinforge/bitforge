from __future__ import unicode_literals
from numbers import Number
import collections

from bitforge.encoding import *
from bitforge.tools import Buffer
from bitforge.errors import *
from bitforge import Address, PublicKey

from .opcode import *
from .instruction import Instruction


BaseScript = collections.namedtuple('Script',
    ['instructions']
)


class Script(BaseScript):

    class Error(BitforgeError):
        pass

    class MissingPushArguments(Error, StringError):
        "Missing arguments for {string} operation"

    class InvalidPushSize(Error, StringError):
        "Push size must be a number, got {string}"

    class InvalidPushData(Error, StringError):
        "Push data must be hex encoded and start with 0x, got {string}"

    class InvalidPushDataLength(Error, NumberError):
        "Push data length doesn't match push size, got {number}"

    class UnknownOpcodeName(Error, StringError):
        "No known operation named {string}"

    def __new__(cls, instructions = None):
        instructions = tuple(instructions if instructions is not None else [])
        return super(Script, cls).__new__(cls, instructions)

    def get_structure(self):
        return tuple(i.opcode if not i.is_push() else 'PUSH' for i in self.instructions)

    @staticmethod
    def create(instructions):
        generic = Script(instructions)
        subcls = Script.classify(generic)
        return subcls(instructions) if subcls else generic

    @staticmethod
    def classify(script):
        for subcls in SCRIPT_SUBCLASSES:
            if subcls.is_valid(script):
                return subcls

        return None

    @staticmethod
    def from_bytes(bytes):
        buffer = Buffer(bytes)
        return Script.from_buffer(buffer)

    @staticmethod
    def from_buffer(buffer):
        instructions = []

        while buffer:
            opcode = Opcode(ord(buffer.read(1)))
            data   = None

            if opcode.is_const_push():
                data = buffer.read(opcode.number)

            elif opcode.is_var_push():
                length_bytes = buffer.read(Opcode.data_length_nbytes(opcode))

                length = decode_int(length_bytes, big_endian = False)
                data   = buffer.read(length)

            instructions.append(Instruction(opcode, data))

        return Script.create(instructions)

    @staticmethod
    def from_string(string):
        instructions = []
        tokens = (i for i in string.split(' '))

        def get_opcode(token):
            try:
                return Opcode.from_name(token)
            except Opcode.UnknownOpcodeName:
                if token.isdigit():
                    return Opcode.const_push_for(int(token))
                else:
                    raise Script.UnknownOpcodeName(token)

        for token in tokens:
            try:
                opcode = get_opcode(token)

                if opcode.is_const_push():
                    hex_bytes = next(tokens)

                    if not hex_bytes.startswith('0x'):
                        raise Script.InvalidPushData(hex_bytes)

                    bytes = decode_hex(hex_bytes[2:])
                    instructions.append(Instruction(opcode, data=bytes))

                elif opcode.is_var_push():
                    size_string = next(tokens)
                    hex_bytes = next(tokens)

                    if not size_string.isdigit():
                        raise Script.InvalidPushSize(size_string)

                    if not hex_bytes.startswith('0x'):
                        raise Script.InvalidPushData(hex_bytes)

                    bytes = decode_hex(hex_bytes[2:])

                    if int(size_string) != len(bytes):
                        raise Script.InvalidPushDataLength(len(bytes))

                    instructions.append(Instruction(opcode, data = bytes))

                else:
                    instructions.append(Instruction(opcode))

            except StopIteration:
                raise Script.MissingPushArguments(token)

        return Script.create(instructions)

    @staticmethod
    def compile(schematic):
        return Script.create(to_instructions(schematic))

    def push_data(self, bytes):
        instruction = Instruction.push_for(bytes)
        self.instructions.push(instruction)

    def remove_opcode_by_data(self, bytes):
        instruction = Instruction.push_for(bytes)
        self.instructions = filter(lambda i: i == instruction, self.instructions)

    def is_push_only(self):
        """
        :returns: if the script is only composed of data pushing opcodes or small int opcodes (OP_0, OP_1, ..., OP_16)
        """
        return all(i.opcode <= OP_16 for i in self.instructions)

    def __repr__(self):
        return str(self.instructions)

    def to_bytes(self):
        return b''.join(i.to_bytes() for i in self.instructions)

    def to_hex(self):
        return encode_hex(self.to_bytes()).decode('utf-8')

    def to_hash(self):
        return ripemd160(sha256(self.to_bytes()))

    def to_string(self):
        return ' '.join(i.to_string() for i in self.instructions)


class PayToPubkeyIn(Script):

    @classmethod
    def create(cls, pubkey, signature):
        schematic = [ signature, pubkey.to_bytes() ]
        return cls(to_instructions(schematic))

    @staticmethod
    def is_valid(script):
        return script.get_structure() == ('PUSH', 'PUSH')

    def get_public_key(self):
        return PublicKey.from_bytes(self.instructions[1].data)

    def get_signature(self):
        return self.instructions[0].data


class PayToPubkeyOut(Script):

    @classmethod
    def create(cls, address):
        schematic = [ OP_DUP, OP_HASH160, address.phash, OP_EQUALVERIFY, OP_CHECKSIG ]
        return cls(to_instructions(schematic))

    @staticmethod
    def is_valid(script):
        return script.get_structure() == (OP_DUP, OP_HASH160, 'PUSH', OP_EQUALVERIFY, OP_CHECKSIG)

    def get_address_hash(self):
        return self.instructions[2].data



class PayToScriptIn(Script):

    @classmethod
    def create(cls, script, signatures):
        schematic = [OP_0] + signatures + [script.to_bytes()]
        return cls(to_instructions(schematic))

    @staticmethod
    def is_valid(script):
        structure = script.get_structure()
        return (
            len(structure) > 2 and
            structure[0] == OP_0 and
            all(op == 'PUSH' for op in structure[1:])
        )

    def get_script(self):
        return Script.from_bytes(self.instructions[-1].data)

    def get_signatures(self):
        return [ i.data for i in self.instructions[1:-1] ]



class PayToScriptOut(Script):

    @classmethod
    def create(cls, script):
        schematic = [ OP_HASH160, script.to_hash(), OP_EQUAL ]
        return cls(to_instructions(schematic))

    @staticmethod
    def is_valid(script):
        return script.get_structure() == (OP_HASH160, 'PUSH', OP_EQUAL)

    def get_script_hash(self):
        return self.instructions[1].data


class OpReturnOut(Script):

    @classmethod
    def create(cls, data):
        schematic = [ OP_RETURN, data ]
        return cls(to_instructions(schematic))

    @staticmethod
    def is_valid(script):
        return script.get_structure() == (OP_RETURN, 'PUSH')

    def get_data(self):
        return self.instructions[1].data


class RedeemMultisig(Script):

    @classmethod
    def create(cls, pubkeys, min_signatures):
        schematic = (
            [ Opcode.for_number(min_signatures) ] +
            [ pubkey.to_bytes() for pubkey in pubkeys ] +
            [ Opcode.for_number(len(pubkeys)) ] +
            [ OP_CHECKMULTISIG ]
        )

        return cls(to_instructions(schematic))

    @staticmethod
    def is_valid(script):
        structure = script.get_structure()

        return (
            len(structure) >= 4 and
            structure[0].is_number() and
            structure[-2].is_number() and
            structure[-1] == OP_CHECKMULTISIG and
            all(op == 'PUSH' for op in structure[1:-2])
        )

    def get_min_signatures(self):
        return self.instructions[0].opcode.number_value()

    def get_public_keys(self):
        return [ PublicKey.from_bytes(i.data) for i in self.instructions[1:-2] ]


SCRIPT_SUBCLASSES = [
    PayToPubkeyIn,
    PayToPubkeyOut,
    PayToScriptIn,
    PayToScriptOut,
    OpReturnOut,
    RedeemMultisig,
]


def to_instructions(schematic):
    instructions = []

    for item in schematic:
        if isinstance(item, Opcode):
            args = (item,)

        elif isinstance(item, Number):
            args = (Opcode(item),)

        elif isinstance(item, basestring):
            args = (Opcode.push_for(len(item)), item)

        elif isinstance(item, tuple):
            if isinstance(item[0], Opcode):
                args = tuple(item)
            else:
                args = (Opcode(item[0]), item[1])

        # TODO catch-all else exception
        instructions.append(Instruction(*args))

    return instructions
