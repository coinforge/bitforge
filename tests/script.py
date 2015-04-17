import pytest

from bitforge.script import Script
from bitforge.opcode import Opcode



class TestScript:
    def test_create_emtpy(self):
        s = Script()
        assert s.instructions == []

    def test_from_string(self):
        s = 'OP_0 OP_PUSHDATA4 3 0x010203 OP_0'
        assert Script.from_string(s).to_string() == s

        s = 'OP_0 OP_PUSHDATA2 3 0x010203 OP_0'
        assert Script.from_string(s).to_string() == s

        s = 'OP_0 OP_PUSHDATA1 3 0x010203 OP_0'
        assert Script.from_string(s).to_string() == s

        s = 'OP_0 3 0x010203 OP_0'
        assert Script.from_string(s).to_string() == s

    def test_to_string_empty(self):
        s = Script()
        assert s.to_string() == ''