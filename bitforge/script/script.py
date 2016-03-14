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

    def equal_without_data(self, other):
        if len(self.instructions) != len(other.instructions):
            return False

        return all(
            self.instructions[i].opcode.equal_without_data(other.instructions[i].opcode)
            for i in range(len(self.instructions))
        )

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

        return Script(instructions)

    @staticmethod
    def pay_to_pubkey_out(address):
        return Script.compile([
            OP_DUP,
            OP_HASH160,
            address.phash,
            OP_EQUALVERIFY,
            OP_CHECKSIG
        ])

    @staticmethod
    def is_pay_to_pubkey_out(script):
        model = Script.pay_to_pubkey_out(Address('a' * 20))
        return script.equal_without_data(model)

    @staticmethod
    def pay_to_pubkey_in(pubkey, signature):
        return Script.compile([
            signature,
            pubkey.to_bytes()
        ])

    @staticmethod
    def is_pay_to_pubkey_in(script):
        model = Script.pay_to_pubkey_in(Address('a' * 20), 'f' * 70)
        return script.equal_without_data(model)

    @staticmethod
    def pay_to_script_out(script):
        return Script.compile([
            OP_HASH160,
            script.to_hash(),
            OP_EQUAL
        ])

    @staticmethod
    def pay_to_script_in(script, signatures):
        return Script.compile([OP_0] + signatures + [script.to_bytes()])

    @staticmethod
    def redeem_multisig(pubkeys, min_signatures):
        return Script.compile(
            [ Opcode.for_number(min_signatures) ] +
            [ pubkey.to_bytes() for pubkey in pubkeys ] +
            [ Opcode.for_number(len(pubkeys)) ] +
            [ OP_CHECKMULTISIG ]
        )

    @staticmethod
    def op_return(data):
        return Script.compile([
            OP_RETURN,
            data
        ])


        # OP_0 here for historical reasons, related to a bug in BTC Core

    #
    #       s.add(Opcode.OP_DUP)
    # .add(Opcode.OP_HASH160)
    # .add(to.hashBuffer)
    # .add(Opcode.OP_EQUALVERIFY)
    # .add(Opcode.OP_CHECKSIG);
#
#     # @staticmethod
#     # def from_string(string):
#     #     script = Script()
#     #     tokens = string.split(' ')
#     #
#     #     i = 0
#     #     while i < len(tokens):
#     #         opcode = Opcode.from_name(tokens[i])
#     #         # TODO: handle unreconized opcodes
#     #         if opcode in [Opcode.OP_PUSHDATA1, Opcode.OP_PUSHDATA2, Opcode.OP_PUSHDATA4]:
#     #             inst = Instruction(opcode, int(tokens[i + 1]), tokens[i + 2])
#     #             script.instructions.append(inst)
#     #             i += 3
#     #         else:
#     #             script.instructions.append(opcode)
#     #             i += 1
#     #
#     #     return script
#
#     @staticmethod
#     def buildScriptHashOut(address):
#         script = Script([
#             Opcode.OP_HASH160
#         ])
#         script.add(Opcode.OP_HASH160)
#         script.add(address.to_bytes())
#         script.add(Opcode.OP_EQUAL)
#         return script
#
#     @staticmethod
#     def buildMultisigOut(pubkeys, thershold, sort = True):
#         if thershold > len(pubkeys):
#             raise ValueError('Number of required signatures must be less than or equal to the number of public keys')
#
#         script = Script()
#         script.add(Opcode.from_int(thershold))
#
#         pubkeys = [(k.to_hex(), k.to_bytes()) for k in pubkeys]
#         pubkeys = sorted(pubkeys) if sort else pubkeys
#         for _, bytes in pubkeys:
#             script.add(bytes)
#
#         script.add(Opcode.from_int(len(pubkeys)))
#         script.add(Opcode.OP_CHECKMULTISIG)
#         return script
#
#
#     def isPubkeyHashOut(self):
#         return self.instructions.length is 5 and \
#                self.instructions[0].opcode is Opcode.OP_DUP and \
#                self.instructions[1].opcode is Opcode.OP_HASH160 and \
#                self.instructions[2].bytes and \
#                self.instructions[2].length is 20 and \
#                self.instructions[3].opcode is Opcode.OP_EQUALVERIFY and \
#                self.instructions[4].opcode is Opcode.OP_CHECKSIG
#
#     def isPublicKeyHashIn(self):
#         return self.instructions.length is 2 and \
#                self.instructions[0].bytes and \
#                self.instructions[0].length >= 0x47 and \
#                self.instructions[0].length <= 0x49 and \
#                PublicKey.is_valid(self.instructions[1].bytes)
#
#     def getPublicKeyHash(self):
#         if not self.getPublicKeyHash():
#             raise ValueError('Can\'t retrieve PublicKeyHash from a non-PKH output')
#         return self.instructions[2].bytes
#
#     def add(self, data):
#         if isinstance(data, Opcode):
#             self.addOpcode(data)
#         else:
#             self.addBytes(data)
#         return self
#
#     def addOpcode(self, opcode):
#         self.instructions.append(Instruction(opcode))
#
#     def addBytes(self, bytes):
#         length = len(bytes)
#         if 0 < length < Opcode.OP_PUSHDATA1.value:
#             opcode = None
#         elif length < pow(2, 8):
#             opcode = OP_PUSHDATA1
#         elif length < pow(2, 16):
#             opcode = OP_PUSHDATA2
#         elif length < pow(2, 32):
#             opcode = OP_PUSHDATA4
#         else:
#             raise ValueError('You can\'t push that much data')
#
#         self.instructions.append(Instruction(opcode, length, bytes))

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
#
#     def to_string(self):
#         return ' '.join(map(str, self.instructions))
#
#     def __repr__(self):
#         return "<Script: %s>" % self.to_string()
