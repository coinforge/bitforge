from bitforge.encoding import *
from bitforge import Input, Script, Output
from bitforge.script.opcode import *

# print repr(encode_int(0xaeae))
# print repr(encode_int(0xaeae, length=5))
# print repr(encode_int(0xaeae, length=5, big_endian=False))


# for n in [2, 2 ** 10, 2 ** 20, 2**40]:
#     print encode_hex(encode_int(n)), encode_hex(encode_varint(n))


def test_input():
    i = Input(
        tx_id     = '15555555555555555555555555555555',
        txo_index = 1,
        script    = Script.from_bytes(chr(OP_PUSHDATA1.number) + '\3' + 'abc')
    )

    actual   = encode_hex(i.to_bytes())
    expected = '5555555555555555555555555555551501000000054c03616263ffffffff'

    assert actual == expected


def test_output():
    o = Output(
        amount = 100,
        script = Script.from_bytes(chr(OP_PUSHDATA1.number) + '\3' + 'abc')
    )

    actual   = encode_hex(o.to_bytes())
    expected = '6400000000000000054c03616263'

    assert actual == expected


test_input()
test_output()
