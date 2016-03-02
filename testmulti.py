from termcolor import colored # not a library dependency, obviously

from bitforge.encoding import *
from bitforge import Input, Script, Output, Transaction, PrivateKey, Address
from bitforge.script.opcode import *
from bitforge import networks

NORMAL_PRIVATE_KEY = '386535361a92ed53ff3b4dc41a9fffdf50cc897eb037b3f5287251c74cb60ac8'

PRIVATE_KEYS_HEX = [
    'd0e44c9e1ab05b194ec537f52d6048aef4eb32bea0bc815ad62bd303bd25539b',
    '5302762f5ddea3c6311e670454b9400682901b0acdb5b6098973ec89d7315b0a',
    '0a8653b645ca225735c193ae3e91d231fc9cbb74756223a140699d7368d5ece2'
]

normal_privkey = PrivateKey.from_hex(NORMAL_PRIVATE_KEY, network=networks.testnet)

privkeys = [
    PrivateKey.from_hex(pk_hex, network = networks.testnet)
    for pk_hex in PRIVATE_KEYS_HEX
]

pubkeys = [ privkey.to_public_key() for privkey in privkeys ]

redeem_script = Script.redeem_multisig(pubkeys, 2)

address = normal_privkey.to_public_key().to_address()
multisig_address = Address.from_script(redeem_script, network=networks.testnet)


print ''

print colored("Regular address privkey:", 'green', attrs=['bold'])
print "\t" + normal_privkey.to_hex()
print ''

print colored("Private keys:", 'green', attrs=['bold'])
for i, privkey in enumerate(privkeys):
    print "\t{0}\t{1}".format(i + 1, privkey.to_hex())

print ''

print colored("Public keys:", 'green', attrs=['bold'])
for i, pubkey in enumerate(pubkeys):
    print "\t{0}\t{1}".format(i + 1, pubkey.to_hex())

print ''

print colored("Addresses:", 'green', attrs=['bold'])
print "\tRegular\t\t" + address.to_string()
print "\tMultisig\t" + multisig_address.to_string()
print ''

print colored("Redeem Script:", 'green', attrs=['bold'])
print "\tHash\t" + encode_hex(redeem_script.to_hash())
print ''


def send_to_multisig_address(prev_tx_id, prev_tx_output_index, amount):
    # Initial script set to redeem script (for signing)
    i = Input(
        tx_id     = prev_tx_id,
        txo_index = prev_tx_output_index,
        script    = Script.pay_to_address_out(address)
    )

    o = Output(amount = amount, script = Script.pay_to_script_out(redeem_script))

    return Transaction([i], [o])


def send_back_to_pubkey_address(prev_tx_id, prev_tx_output_index, amount):
    i = Input(
        tx_id     = prev_tx_id,
        txo_index = prev_tx_output_index,
        script    = redeem_script
    )

    o = Output(amount = amount, script = Script.pay_to_address_out(address))

    return Transaction([i], [o])


first_transaction = send_to_multisig_address(
    prev_tx_id           = '912b49e826425a1e6598bc19dfcaefa58cc2e512f2b6f00b1510c862dd9494eb',
    prev_tx_output_index = 0,
    amount               = 30000
)

print colored("Send to multisig address:", 'green', attrs=['bold'])
print "\t" + first_transaction.signed(0, normal_privkey).to_hex()
print ''


second_transaction = send_back_to_pubkey_address(
    prev_tx_id           = 'd9a78501ba9601391094fe4a369ab8767822196561ceca3b64e446ea6785a085',
    prev_tx_output_index = 0,
    amount               = 20000
)

print colored("Send to multisig address:", 'green', attrs=['bold'])
print "\t" + second_transaction.signed_multisig(0, privkeys[1:], redeem_script).to_hex()
print ''


# print 'btw, script is', redeem_script
# print ''
# print len(redeem_script.to_bytes())

    #
# new_tx = new_transaction('b206ec7384d95cfd71e21743ce5ccbb8afa363c7c20724016984d12a37dcf77b')
# print 'WITH SIGNATURE'
# print new_tx.to_hex()
# print '---'
#
# # print ''
# # print 'PAY TO ADDRESS OUT'
# # print Script.pay_to_address_out(address).to_hex()
#
# # print ''
# # print 'PAY TO ADDRESS IN'
# # print Script.pay_to_address_in(address).to_hex()
#
#
# # print ''
# # print 'DECODED SOMETHING'
# # print Script.from_bytes(decode_hex('023abd0b238c5e93e4d1d9f06e9d743941e5d3f23d0b5371a0f87ac56106373829'))

print 'finally', Script.pay_to_script_out(redeem_script).to_hex()
