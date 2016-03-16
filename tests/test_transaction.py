from pytest import raises

from bitforge import PrivateKey
from bitforge import Transaction, Input, Output, Script
from bitforge.transaction import AddressOutput, ScriptOutput, DataOutput
from bitforge.transaction import AddressInput, ScriptInput
from bitforge.script import PayToPubkeyOut, PayToScriptOut, OpReturnOut
from bitforge.script import PayToPubkeyIn, PayToScriptIn
from bitforge.script.opcode import OP_0


class MockInput(Input):
    def __new__(cls):
        return super(MockInput, cls).__new__(cls, '', 0, Script())

class MockOutput(Output):
    def __new__(cls):
        return super(MockOutput, cls).__new__(cls, 1000, Script())

class MockTransaction(Transaction):
    def __new__(cls, inputs = [ MockInput() ], outputs = [ MockOutput() ], lock_time = 0, version = 1):
        return super(MockTransaction, cls).__new__(cls, inputs, outputs, lock_time, version)


class TestTransaction:
    def test_create(self):
        MockTransaction()

    def test_no_inputs(self):
        with raises(Transaction.NoInputs):
            Transaction([], [])

    def test_no_outputs(self):
        with raises(Transaction.NoOutputs):
            Transaction([ MockInput() ], [])

    def test_invalid_lock_time(self):
        with raises(Transaction.InvalidLockTime):
            Transaction([ MockInput() ], [ MockOutput() ], -1)


class TestInput:
    def test_create(self):
        MockInput()

    def test_classify(self):
        privkey = PrivateKey()
        pubkey = privkey.to_public_key()
        address = pubkey.to_address()
        signature = 'foo'
        script = Script.compile([ OP_0 ])

        i_addr = Input.create('1' * 32, 0, PayToPubkeyIn.create(address, signature))
        assert isinstance(i_addr, AddressInput)

        i_script = Input.create('1' * 32, 0, PayToScriptIn.create(script, [signature]))
        assert isinstance(i_script, ScriptInput)


class TestOutput:
    def test_create(self):
        MockOutput()

    def test_too_much_data(self):
        with raises(DataOutput.TooMuchData):
            DataOutput.create("0" * 81)

    def test_classify(self):
        privkey = PrivateKey()
        pubkey = privkey.to_public_key()
        address = pubkey.to_address()
        script = Script()

        o_addr = Output.create(1, PayToPubkeyOut.create(address))
        assert isinstance(o_addr, AddressOutput)

        o_script = Output.create(1, PayToScriptOut.create(script))
        assert isinstance(o_script, ScriptOutput)

        o_data = Output.create(1, OpReturnOut.create('data'))
        assert isinstance(o_data, DataOutput)
