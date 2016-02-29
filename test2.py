from bitforge.encoding import *
from bitforge import Input, Script, Output, Transaction, PrivateKey
from bitforge.script.opcode import *
from bitforge import networks


PK_HEX = 'd0e44c9e1ab05b194ec537f52d6048aef4eb32bea0bc815ad62bd303bd25539b'

privkey = PrivateKey.from_hex(PK_HEX, network = networks.testnet)
pubkey  = privkey.to_public_key()
address = pubkey.to_address()

print 'PRIVATE KEY\t\t', privkey.to_hex()
print 'PUBLIC KEY\t\t', pubkey.to_hex()
print ''
print 'ADDRESS\t\t\t', address.to_string()
print 'ADDRESS HEX\t\t', address.to_hex()
print 'ADDRESS RAW\t\t', encode_hex(address.phash)
print ''

print 'SIGNED "foobar"'
print encode_hex(privkey.sign('foobar'))
# privkey.verify(privkey.sign('foobar'), 'foobar')
print ''
# def fake_previous_transaction():
#     iscript = Script.compile([
#         '304502206e21798a42fae0e854281abd38bacd1aeed3ee3738d9e1446618c4571d10',
#         '90db022100e2ac980643b0b82c0e88ffdfec6b64e3e6ba35e7ba5fdd7d5d6cc8d25c6b241501'
#     ])
#
#     i = Input(
#         tx_id     = '3258b45c2558c3d6a6876c288bb784d85a72a33f8dba5b6468161e976d8e7bca',
#         txo_index = 0,
#         script    = iscript
#     )
#
#     o = Output(amount = 100, script = oscript)
#
#     return Transaction(inputs = [i], outputs = [o])

# prev_tx = previous_transaction()


def new_transaction(prev_tx_id):
    # Initial script set to previous output script (for signing)
    i = Input(
        tx_id     = prev_tx_id,
        txo_index = 1,
        script    = Script.pay_to_address_out(address)
    )
    #OP_DUP OP_HASH160 e0edcb38d4cebca2519bedc3533c746fa19f6777 OP_EQUALVERIFY OP_CHECKSIG

    o = Output(amount = 1000, script = Script.pay_to_address_out(address))

    print "WITHOUT SIGNATURE"
    print Transaction([i], [o]).to_hex()
    print '---'

    return Transaction([i], [o]).signed(0, privkey)


new_tx = new_transaction('b206ec7384d95cfd71e21743ce5ccbb8afa363c7c20724016984d12a37dcf77b')
print 'WITH SIGNATURE'
print new_tx.to_hex()
print '---'

# print ''
# print 'PAY TO ADDRESS OUT'
# print Script.pay_to_address_out(address).to_hex()

# print ''
# print 'PAY TO ADDRESS IN'
# print Script.pay_to_address_in(address).to_hex()


# print ''
# print 'DECODED SOMETHING'
# print Script.from_bytes(decode_hex('023abd0b238c5e93e4d1d9f06e9d743941e5d3f23d0b5371a0f87ac56106373829'))
