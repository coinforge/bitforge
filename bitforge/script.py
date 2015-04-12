import binascii
from enum import Enum
from opcode import Opcode
from pubkey import PublicKey
from utils.intbytes import int_to_bytes

# TODO: s/chunk/Instruction/???
class Chunk(object):
    def __init__(self, opcode, length = None, bytes = None):
        self.opcode = opcode
        self.length = length
        self.bytes = bytes

    def toBytes(self):
        if not self.bytes:
            return int_to_bytes(self.opcode.value)

        return int_to_bytes(self.length) + self.bytes

    # TODO: s/__str__/to string, code, asm, etc
    def __str__(self):
        if not self.bytes:
            return self.opcode.name

        ret = []
        if self.opcode and self.opcode.pushesData():
            ret.append(self.opcode.name)
        ret.append(self.length)
        ret.append('0x' + binascii.hexlify(self.bytes))
        return ' '.join(map(str, ret))


    def __repr__(self):
        return '<Chunk: %s %s %s>' % (self.opcode, self.length, self.bytes)


# TODO: caress it a little bit
class Script(object):

    def __init__(self):
        self.chunks = []

    # TODO from script, from code, etc...
    @staticmethod
    def fromString(string):
        script = Script()
        tokens = string.split(' ') # TODO: split()

        i = 0
        while i < len(tokens):
            # TODO: check invalid, check empty!
            opcode = Opcode.fromString(tokens[i])
            if opcode in [Opcode.OP_PUSHDATA1, Opcode.OP_PUSHDATA2, Opcode.OP_PUSHDATA4]:
                chunk = Chunk(opcode, int(tokens[i + 1]), tokens[i + 2])
                script.chunks.append(chunk)
                i += 3
            else:
                script.chunks.append(opcode)
                i += 1

        return script

    # TODO: add _ (private methods) wherever necessary
    # TODO: functionize it all!
    # TODO: naming fromBLEBLE
    @staticmethod
    def buildScriptHashOut(address):
        script = Script()
        script.add(Opcode.OP_HASH160)
        script.add(address.toBytes())
        script.add(Opcode.OP_EQUAL)
        return script

    # TODO: naming
    @staticmethod
    def buildMultisigOut(pubkeys, thershold, sort = True):
        if thershold > len(pubkeys):
            raise ValueError('Number of required signatures must be less than or equal to the number of public keys')

        script = Script()
        script.add(Opcode.fromSmallInt(thershold))

        pubkeys = [(k.toHex(), k.toBytes()) for k in pubkeys]
        pubkeys = sorted(pubkeys) if sort else pubkeys
        for _, bytes in pubkeys:
            script.add(bytes)

        script.add(Opcode.fromSmallInt(len(pubkeys)))
        script.add(Opcode.OP_CHECKMULTISIG)
        return script


    # TODO: naming?
    def isPubkeyHashOut(self):
        return self.chunks.length is 5 and \
               self.chunks[0].opcode is Opcode.OP_DUP and \
               self.chunks[1].opcode is Opcode.OP_HASH160 and \
               self.chunks[2].bytes and \
               self.chunks[2].length is 20 and \
               self.chunks[3].opcode is Opcode.OP_EQUALVERIFY and \
               self.chunks[4].opcode is Opcode.OP_CHECKSIG

    def isPublicKeyHashIn(self):
        return self.chunks.length is 2 and \
               self.chunks[0].bytes and \
               self.chunks[0].length >= 0x47 and \
               self.chunks[0].length <= 0x49 and \
               PublicKey.isValid(self.chunks[1].bytes)

    def getPublicKeyHash(self):
        if not self.getPublicKeyHash():
            raise ValueError('Can\'t retrieve PublicKeyHash from a non-PKH output')
        return self.chunks[2].bytes

    # TODO: wooooot (_ maybe)
    def add(self, data):
        if isinstance(data, Opcode):
            self.addOpcode(data)
        else:
            self.addBytes(data)
        return self

    def addOpcode(self, opcode):
        self.chunks.append(Chunk(opcode))

    # TODO: s/app/append,push
    # TODO: kpooooow ** 2
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

        self.chunks.append(Chunk(opcode, length, bytes))

    def toBytes(self):
        return ''.join(map(Chunk.toBytes, self.chunks))

    # TODO: to algo
    def __str__(self):
        return ' '.join(map(str, self.chunks))

    def __repr__(self):
        return "<Script: %s>" % str(self)
