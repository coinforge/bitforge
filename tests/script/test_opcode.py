from __future__ import unicode_literals

from pytest import raises

from bitforge.script.opcode import *


class TestOpcode:

    def test_create(self):
        assert Opcode(80) == OP_RESERVED

    def test_create_invalid(self):
        with raises(Opcode.UnknownOpcodeNumber):
            Opcode(256)

    def test_name(self):
        assert Opcode.const_push_for(3).name == '_PUSH_3_BYTES'
        assert OP_0.name == 'OP_0'
        assert OP_RESERVED.name == 'OP_RESERVED'

    def test_is_number(self):
        assert OP_0.is_number() is True
        assert OP_16.is_number() is True
        assert OP_RESERVED.is_number() is False

    def test_number_value(self):
        with raises(Opcode.WrongOpcodeType):
            OP_RESERVED.number_value()

        assert OP_0.number_value() == 0
        assert OP_16.number_value() == 16

    def test_is_push(self):
        assert Opcode.const_push_for(10).is_push() is True
        assert Opcode.var_push_for(36).is_push() is True
        assert OP_RESERVED.is_push() is False

    def test_is_const_push(self):
        assert Opcode(75).is_const_push() is True
        assert OP_PUSHDATA1.is_const_push() is False

    def test_is_var_push(self):
        for opcode in (OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4):
            assert opcode.is_var_push() is True

        assert OP_RESERVED.is_var_push() is False

    def test_ordering(self):
        assert OP_0 < OP_1
        assert OP_1 > OP_0

    def test_bytes(self):
        assert OP_1.bytes == b'\x51'

    def test_for_number(self):
        with raises(ValueError):
            Opcode.for_number(17)
        assert Opcode.for_number(10) == Opcode(90)

    def test_from_name(self):
        with raises(Opcode.UnknownOpcodeName):
            Opcode.from_name('OP_FOO')

        assert Opcode.from_name('OP_1') == OP_1

    def test_const_push_for(self):
        with raises(Opcode.InvalidConstPushLength):
            Opcode.const_push_for(0)

        with raises(Opcode.InvalidConstPushLength):
            Opcode.const_push_for(76)

        assert Opcode.const_push_for(10) == Opcode(10)

    def test_var_push_for(self):
        with raises(Opcode.InvalidPushLength):
            Opcode.var_push_for(0)

        assert Opcode.var_push_for(1) == OP_PUSHDATA1
        assert Opcode.var_push_for(1 << 15) == OP_PUSHDATA2
        assert Opcode.var_push_for(1 << 31) == OP_PUSHDATA4

        with raises(Opcode.InvalidPushLength):
            Opcode.var_push_for(1 << 64)

    def test_data_length_max(self):
        assert Opcode.data_length_max(Opcode.const_push_for(5)) == 5
        assert Opcode.data_length_max(OP_RESERVED) == 0
        assert Opcode.data_length_max(OP_PUSHDATA1) == 255

    def test_data_length_nbytes(opcode):
        assert Opcode.data_length_nbytes(OP_PUSHDATA1) == 1
        assert Opcode.data_length_nbytes(OP_PUSHDATA2) == 2
        assert Opcode.data_length_nbytes(OP_PUSHDATA4) == 4

        with raises(Opcode.WrongOpcodeType):
            Opcode.data_length_nbytes(OP_0)
