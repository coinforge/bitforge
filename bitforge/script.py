import binascii
from enum import Enum
from opcode import Opcode
from pubkey import PublicKey
from utils.intbytes import int_to_bytes

class Instruction(object):
    def __init__(self, opcode, length = None, bytes = None):
        self.opcode = opcode
        self.length = length
        self.bytes = bytes

    def toBytes(self):
        if not self.bytes:
            return int_to_bytes(self.opcode.value)

        return int_to_bytes(self.length) + self.bytes

    def __str__(self):
        if not self.bytes:
            return self.opcode.name

        ret = []
        if self.opcode and self.opcode.is_push():
            ret.append(self.opcode.name)
        ret.append(self.length)
        ret.append('0x' + binascii.hexlify(self.bytes))
        return ' '.join(map(str, ret))


    def __repr__(self):
        return '<Instruction: %s %s %s>' % (self.opcode, self.length, self.bytes)


class Script(object):

    def __init__(self):
        self.instructions = []

    @staticmethod
    def from_string(string):
        script = Script()
        tokens = string.split(' ')

        i = 0
        while i < len(tokens):
            opcode = Opcode.from_name(tokens[i])
            # TODO: handle unreconized opcodes
            if opcode in [Opcode.OP_PUSHDATA1, Opcode.OP_PUSHDATA2, Opcode.OP_PUSHDATA4]:
                inst = Instruction(opcode, int(tokens[i + 1]), tokens[i + 2])
                script.instructions.append(inst)
                i += 3
            else:
                script.instructions.append(opcode)
                i += 1

        return script

    @staticmethod
    def buildScriptHashOut(address):
        script = Script()
        script.add(Opcode.OP_HASH160)
        script.add(address.to_bytes())
        script.add(Opcode.OP_EQUAL)
        return script

    @staticmethod
    def buildMultisigOut(pubkeys, thershold, sort = True):
        if thershold > len(pubkeys):
            raise ValueError('Number of required signatures must be less than or equal to the number of public keys')

        script = Script()
        script.add(Opcode.from_int(thershold))

        pubkeys = [(k.to_hex(), k.to_bytes()) for k in pubkeys]
        pubkeys = sorted(pubkeys) if sort else pubkeys
        for _, bytes in pubkeys:
            script.add(bytes)

        script.add(Opcode.from_int(len(pubkeys)))
        script.add(Opcode.OP_CHECKMULTISIG)
        return script


    def isPubkeyHashOut(self):
        return self.instructions.length is 5 and \
               self.instructions[0].opcode is Opcode.OP_DUP and \
               self.instructions[1].opcode is Opcode.OP_HASH160 and \
               self.instructions[2].bytes and \
               self.instructions[2].length is 20 and \
               self.instructions[3].opcode is Opcode.OP_EQUALVERIFY and \
               self.instructions[4].opcode is Opcode.OP_CHECKSIG

    def isPublicKeyHashIn(self):
        return self.instructions.length is 2 and \
               self.instructions[0].bytes and \
               self.instructions[0].length >= 0x47 and \
               self.instructions[0].length <= 0x49 and \
               PublicKey.is_valid(self.instructions[1].bytes)

    def getPublicKeyHash(self):
        if not self.getPublicKeyHash():
            raise ValueError('Can\'t retrieve PublicKeyHash from a non-PKH output')
        return self.instructions[2].bytes

    def add(self, data):
        if isinstance(data, Opcode):
            self.addOpcode(data)
        else:
            self.addBytes(data)
        return self

    def addOpcode(self, opcode):
        self.instructions.append(Instruction(opcode))

    def addBytes(self, bytes):
        length = len(bytes)
        if 0 < length < Opcode.OP_PUSHDATA1.value:
            opcode = None
        elif length < pow(2, 8):
            opcode = OP_PUSHDATA1
        elif length < pow(2, 16):
            opcode = OP_PUSHDATA2
        elif length < pow(2, 32):
            opcode = OP_PUSHDATA4
        else:
            raise ValueError('You can\'t push that much data')

        self.instructions.append(Instruction(opcode, length, bytes))

    def to_bytes(self):
        return ''.join(map(Instruction.toBytes, self.instructions))

    def to_string(self):
        return ' '.join(map(str, self.instructions))

    def __repr__(self):
        return "<Script: %s>" % self.to_string()
