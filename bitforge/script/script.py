from __future__ import unicode_literals
from numbers import Number
import collections

from bitforge.encoding import *
from bitforge.tools import Buffer
from bitforge.errors import *
from bitforge import Address

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
        "Push data must be hexa encoded and start with 0x, got {string}"

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

        return Script(instructions)

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

        return Script(instructions)

    @staticmethod
    def compile(schematic):
        return Script(to_instructions(schematic))

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

    @staticmethod
    def is_valid(script):
        return script.get_structure() == ('PUSH', 'PUSH')

    def __new__(cls, pubkey, signature):
        schematic = [ signature, pubkey.to_bytes() ]
        return super(PayToPubkeyIn, cls).__new__(cls, to_instructions(schematic))


class PayToPubkeyOut(Script):

    @staticmethod
    def is_valid(script):
        return script.get_structure() == (OP_DUP, OP_HASH160, 'PUSH', OP_EQUALVERIFY, OP_CHECKSIG)

    def __new__(cls, address):
        schematic = [
            OP_DUP,
            OP_HASH160,
            address.phash,
            OP_EQUALVERIFY,
            OP_CHECKSIG
        ]

        return super(PayToPubkeyOut, cls).__new__(cls, to_instructions(schematic))


class PayToScriptIn(Script):

    @staticmethod
    def is_valid(script):
        structure = script.get_structure()
        return (
            len(structure) > 2 and
            structure[0] == OP_0 and
            all(op == 'PUSH' for op in structure[1:])
        )

    def __new__(cls, script, signatures):
        schematic = [OP_0] + signatures + [script.to_bytes()]
        return super(PayToScriptIn, cls).__new__(cls, to_instructions(schematic))


class PayToScriptOut(Script):

    @staticmethod
    def is_valid(script):
        return script.get_structure() == (OP_HASH160, 'PUSH', OP_EQUAL)

    def __new__(cls, script):
        schematic = [ OP_HASH160, script.to_hash(), OP_EQUAL ]
        return super(PayToScriptOut, cls).__new__(cls, to_instructions(schematic))


class OpReturnOut(Script):

    @staticmethod
    def is_valid(script):
        return script.get_structure() == (OP_RETURN, 'PUSH')

    def __new__(cls, data):
        schematic = [ OP_RETURN, data ]
        return super(OpReturnOut, cls).__new__(cls, to_instructions(schematic))


class RedeemMultisig(Script):

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

    def __new__(cls, pubkeys, min_signatures):
        schematic = (
            [ Opcode.for_number(min_signatures) ] +
            [ pubkey.to_bytes() for pubkey in pubkeys ] +
            [ Opcode.for_number(len(pubkeys)) ] +
            [ OP_CHECKMULTISIG ]
        )

        return super(RedeemMultisig, cls).__new__(cls, to_instructions(schematic))


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
