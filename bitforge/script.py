import binascii, collections
from numbers import Number
from pubkey import PublicKey
from opcode import *
from encoding import *
from tools import Buffer
from errors import *


BaseInstruction = collections.namedtuple('BaseInstruction', ['opcode', 'data'])

class Instruction(BaseInstruction):

    class Error(BitforgeError):
        pass

    class TypeError(Error, ObjectError):
        "Expected an Opcode, got {object}"

    class UnexpectedData(Error, ObjectError):
        "Instruction got data with opcode {object}, which does not push data"

    class InvalidDataLength(Error):
        "Opcode {opcode} can't push {data_length} bytes (max/exactly {data_length_max})"

        def prepare(self, opcode, data_length, data_length_max):
            self.opcode = opcode
            self.data_length = data_length
            self.data_length_max = data_length_max


    def __new__(cls, opcode, data = None):
        if not isinstance(opcode, Opcode):
            raise Instruction.TypeError(opcode)

        if opcode.is_push():
            length = len(data)
            expect = Opcode.data_length_max(opcode)

            if (opcode.is_const_push() and length != expect) or \
               (opcode.is_var_push and not (0 <= length <= expect)):
                raise Instruction.InvalidDataLength(opcode, length, expect)

        elif data is not None:
            raise Instruction.UnexpectedData(opcode)

        return super(Instruction, cls).__new__(cls, opcode, data)

    def to_bytes(self):
        opcode_byte = chr(self.opcode.number)

        if self.opcode.is_const_push():
            return opcode_byte + self.data

        elif self.opcode.is_var_push():
            length_nbytes = Opcode.data_length_nbytes(self.opcode)

            length_bytes = encode_int(
                len(self.data),
                big_endian = False
            ).rjust(length_nbytes, '\0')

            return opcode_byte + length_bytes + self.data

        else:
            return opcode_byte

    def to_hex(self):
        return encode_hex(self.to_bytes())

    def to_string(self):
        if self.opcode.is_push():
            data_len = len(self.data)
            data_hex = "0x" + encode_hex(self.data)

            if self.opcode.is_const_push():
                return "%d %s" % (data_len, data_hex)

            elif self.opcode.is_var_push():
                return "%s %d %s" % (self.opcode.name, data_len, data_hex)
        else:
            return self.opcode.name

    def __eq__(self, other):
        return self.opcode == other.opcode and self.data == other.data

    def __hash__(self):
        return hash((self.opcode, self.data))

    def __repr__(self):
        if self.opcode.is_push():
            return "<Instruction: %s '%s'>" % (self.opcode.name, encode_hex(self.data))
        else:
            return "<Instruction: %s>" % (self.opcode.name)


class Script(object):
    def __init__(self, instructions = None):
        self.instructions = instructions if instructions is not None else []

    @staticmethod
    def from_bytes(bytes):
        buffer       = Buffer(bytes)
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
    def build(*schematic):
        instructions = []

        for item in schematic:
            if isinstance(item, Opcode):
                args = (item,)

            elif isinstance(item, Number):
                args = (Opcode(item),)

            elif isinstance(item, str):
                args = (Opcode.push_for(len(item)), item)

            elif isinstance(item, tuple):
                if isinstance(item[0], Opcode):
                    args = tuple(item)
                else:
                    args = (Opcode(item[0]), item[1])

            instructions.append(Instruction(*args))

        return Script(instructions)

    @staticmethod
    def pay_to_address_out(address):
        return Script.build(
            OP_DUP,
            OP_HASH160,
            address.phash,
            OP_EQUALVERIFY
        )

    @staticmethod
    def pay_to_address_in(pubkey, signature):
        return Script.build(
            signature.to_bytes(),
            pubkey.to_bytes()
        )
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
#
    def to_bytes(self):
        return ''.join(i.to_bytes() for i in self.instructions)
#
#     def to_string(self):
#         return ' '.join(map(str, self.instructions))
#
#     def __repr__(self):
#         return "<Script: %s>" % self.to_string()
