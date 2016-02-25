import pytest, inspect
from pytest import raises, fixture, fail

from bitforge.script import Script, Instruction
from bitforge.script.opcode import *
import bitforge.script.opcode as opcode_module
from bitforge.encoding import *
from bitforge.tools import Buffer


class TestScript:
    def test_create_emtpy(self):
        s = Script()
        assert s.instructions == []

    def test_binary_single(self):
        s = Script.from_bytes('\0')
        assert s.instructions == [Instruction(OP_0)]

    def test_binary_const_pushes(self):
        for length in xrange(1, 76):
            opcode = Opcode(length)
            string = 'a' * length

            s = Script.from_bytes(chr(length) + string)

            assert s.instructions == [Instruction(opcode, string)]

    def test_binary_var_pushes(self):
        s1 = Script.from_bytes(chr(OP_PUSHDATA1.number) + '\3' + 'abc')
        assert s1.instructions == [Instruction(OP_PUSHDATA1, 'abc')]

        s2 = Script.from_bytes(chr(OP_PUSHDATA2.number) + '\3\0' + 'abc')
        assert s2.instructions == [Instruction(OP_PUSHDATA2, 'abc')]

        s2 = Script.from_bytes(chr(OP_PUSHDATA4.number) + '\3\0\0\0' + 'abc')
        assert s2.instructions == [Instruction(OP_PUSHDATA4, 'abc')]

        with raises(Buffer.InsufficientData):
            Script.from_bytes(chr(OP_PUSHDATA1.number) + '\3' + 'a')

        with raises(Buffer.InsufficientData):
            Script.from_bytes(chr(OP_PUSHDATA2.number) + '\3\0' + 'a')

        with raises(Buffer.InsufficientData):
            Script.from_bytes(chr(OP_PUSHDATA4.number) + '\3\0\0\0' + 'a')

    def test_binary_all_nonpush_opcodes(self):
        opcodes = []
        for name, value in inspect.getmembers(opcode_module):
            if isinstance(value, Opcode) and not value.is_push():
                opcodes.append(value)

        bytes = ''.join(chr(opcode.number) for opcode in opcodes)

        s = Script.from_bytes(bytes)
        assert s.instructions == map(Instruction, opcodes)

    # def test_from_string(self):
    #     s = 'OP_0 OP_PUSHDATA4 3 0x010203 OP_0'
    #     assert Script.from_string(s).to_string() == s
    #
    #     s = 'OP_0 OP_PUSHDATA2 3 0x010203 OP_0'
    #     assert Script.from_string(s).to_string() == s
    #
    #     s = 'OP_0 OP_PUSHDATA1 3 0x010203 OP_0'
    #     assert Script.from_string(s).to_string() == s
    #
    #     s = 'OP_0 3 0x010203 OP_0'
    #     assert Script.from_string(s).to_string() == s
    #
    # def test_to_string_empty(self):
    #     s = Script()
    #     assert s.to_string() == ''
