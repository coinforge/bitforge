import pytest, inspect
from pytest import raises, fixture, fail

from bitforge import Transaction, Input, Output, Script


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
