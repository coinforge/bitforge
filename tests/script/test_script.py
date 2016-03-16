import pytest, inspect
from pytest import raises, fixture, fail

from bitforge.script import *
from bitforge.script.script import SCRIPT_SUBCLASSES
from bitforge.script.opcode import *
import bitforge.script.opcode as opcode_module
from bitforge.encoding import *
from bitforge.tools import Buffer
from bitforge import Address, PrivateKey


class TestScript:
    def test_create_emtpy(self):
        s = Script()
        assert s.instructions == tuple()

    def test_binary_single(self):
        s = Script.from_bytes(b'\0')
        assert s.instructions == (Instruction(OP_0),)

    def test_binary_const_pushes(self):
        for length in range(1, 76):
            opcode = Opcode(length)
            string = b'a' * length

            op_bytes = bytes(bytearray([length]))
            s = Script.from_bytes(op_bytes + string)

            assert s.instructions == (Instruction(opcode, string),)

    def test_binary_var_pushes(self):
        s1 = Script.from_bytes(OP_PUSHDATA1.bytes + b'\3' + b'abc')
        assert s1.instructions == (Instruction(OP_PUSHDATA1, b'abc'),)

        s2 = Script.from_bytes(OP_PUSHDATA2.bytes + b'\3\0' + b'abc')
        assert s2.instructions == (Instruction(OP_PUSHDATA2, b'abc'),)

        s2 = Script.from_bytes(OP_PUSHDATA4.bytes + b'\3\0\0\0' + b'abc')
        assert s2.instructions == (Instruction(OP_PUSHDATA4, b'abc'),)

        with raises(Buffer.InsufficientData):
            Script.from_bytes(OP_PUSHDATA1.bytes + b'\3' + b'a')

        with raises(Buffer.InsufficientData):
            Script.from_bytes(OP_PUSHDATA2.bytes + b'\3\0' + b'a')

        with raises(Buffer.InsufficientData):
            Script.from_bytes(OP_PUSHDATA4.bytes + b'\3\0\0\0' + b'a')

    def test_binary_all_nonpush_opcodes(self):
        opcodes = []
        for name, value in inspect.getmembers(opcode_module):
            if isinstance(value, Opcode) and not value.is_push():
                opcodes.append(value)

        bytes = b''.join(opcode.bytes for opcode in opcodes)

        s = Script.from_bytes(bytes)
        assert s.instructions == tuple(map(Instruction, opcodes))

    def test_from_string(self):

        def test_script_string(string, instructions):
            script = Script.from_string(string)
            assert script.to_string() == string
            assert len(script.instructions) == instructions

        test_script_string('OP_0 OP_PUSHDATA4 3 0x010203 OP_0', 3)
        test_script_string('OP_0 OP_PUSHDATA2 3 0x010203 OP_0', 3)
        test_script_string('OP_0 OP_PUSHDATA1 3 0x010203 OP_0', 3)
        test_script_string('OP_0 3 0x010203 OP_0', 3)

        with raises(Script.UnknownOpcodeName):
            Script.from_string('OP_99')

        with raises(Script.MissingPushArguments):
            Script.from_string('OP_PUSHDATA1')

        with raises(Script.MissingPushArguments):
            Script.from_string('OP_PUSHDATA1 3')

        with raises(Script.InvalidPushDataLength):
            Script.from_string('OP_PUSHDATA1 3 0x01020302')

        with raises(Script.InvalidPushData):
            Script.from_string('OP_PUSHDATA1 3 010203')

        with raises(Script.InvalidPushData):
            Script.from_string('3 010203')

    def test_is_push_only(self):
        script = Script.from_string('OP_1 OP_16')
        assert script.is_push_only() is True

        script = Script.from_string('OP_PUSHDATA1 1 0x01')
        assert script.is_push_only() is True

        script = Script.from_string('OP_1 OP_RETURN')
        assert script.is_push_only() is False

    def test_is_pay_to_pubkey_in(self):
        address = PrivateKey().to_address()
        yes = [
            PayToPubkeyIn.create(address, b'foo'),
            PayToPubkeyIn.create(address, b'bar')
        ]

        no = [
            Script(),
            PayToPubkeyOut.create(Address('a' * 20))
        ]

        assert all(map(PayToPubkeyIn.is_valid, yes))
        assert not any(map(PayToPubkeyIn.is_valid, no))

    def test_is_pay_to_pubkey_out(self):
        address = PrivateKey().to_address()
        yes = [
            PayToPubkeyOut.create(address),
            PayToPubkeyOut.create(address)
        ]

        no = [
            Script(),
            PayToPubkeyIn.create(address, b'foo')
        ]

        assert all(map(PayToPubkeyOut.is_valid, yes))
        assert not any(map(PayToPubkeyOut.is_valid, no))

    def test_is_pay_to_script_out(self):
        address = PrivateKey().to_address()
        embedded = PayToPubkeyOut.create(address)

        yes = [ PayToScriptOut.create(embedded) ]

        no = [
            Script(),
            PayToPubkeyOut.create(address),
            PayToScriptIn.create(embedded, [ b'foo' ])
        ]

        assert all(map(PayToScriptOut.is_valid, yes))
        assert not any(map(PayToScriptOut.is_valid, no))

    def test_is_pay_to_script_in(self):
        address = PrivateKey().to_address()
        embedded = PayToPubkeyOut.create(address)

        yes = [
            PayToScriptIn.create(embedded, [ b'foo' ]),
            PayToScriptIn.create(Script.compile([ b'bar' ]), [ b'foo' ]),
            PayToScriptIn.create(Script.compile([ b'baz' ]), [ b'one', b'two' ]),
        ]

        no = [
            Script(),
            PayToPubkeyIn.create(address, b'foo'),
            PayToScriptOut.create(Script())
        ]

        assert all(map(PayToScriptIn.is_valid, yes))
        assert not any(map(PayToScriptIn.is_valid, no))

    def test_p2pkh_getters(self):
        privkey = PrivateKey()
        pubkey = privkey.to_public_key()
        address = pubkey.to_address()
        signature = 'foo'

        i_script = PayToPubkeyIn.create(pubkey, signature)
        o_script = PayToPubkeyOut.create(address)

        assert i_script.get_public_key() == pubkey
        assert i_script.get_signature() == signature
        assert o_script.get_address_hash() == address.phash

    def test_p2sh_getters(self):
        privkey = PrivateKey()
        pubkey = privkey.to_public_key()
        address = pubkey.to_address()
        embedded = Script.compile([ OP_0, 'bar', OP_1 ])
        signatures = [ 'foo', 'bar' ]

        i_script = PayToScriptIn.create(embedded, signatures)
        o_script = PayToScriptOut.create(embedded)

        assert i_script.get_script() == embedded
        assert i_script.get_signatures() == signatures
        assert o_script.get_script_hash() == embedded.to_hash()

    def test_op_return_getters(self):
        data = 'foo bar baz'
        script = OpReturnOut.create(data)
        assert script.get_data() == data

    def test_redeem_multisig_getters(self):
        privkeys = [ PrivateKey(), PrivateKey() ]
        pubkeys = [ privkey.to_public_key() for privkey in privkeys ]
        signatures = [ 'foo', 'bar' ]

        script = RedeemMultisig.create(pubkeys, 2)

        assert script.get_min_signatures() == 2
        assert script.get_public_keys() == pubkeys

    def test_classify(self):
        privkey = PrivateKey()
        pubkey = privkey.to_public_key()
        address = pubkey.to_address()
        signature = 'foo'
        script = RedeemMultisig.create([ pubkey ], 1)

        class_to_arguments = {
            PayToPubkeyIn : [ pubkey, signature ],
            PayToPubkeyOut: [ address ],
            PayToScriptIn : [ script, [signature] ],
            PayToScriptOut: [ script ],
            RedeemMultisig: [ [pubkey], 1 ],
            OpReturnOut   : [ 'data' ]
        }

        for cls, args in class_to_arguments.items():
            special = cls.create(*args)
            generic = Script(special.instructions)

            assert Script.classify(special) == Script.classify(generic) == cls
            assert isinstance(Script.create(special.instructions), cls)
