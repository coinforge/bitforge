from __future__ import print_function

from bitforge.encoding import *
from bitforge import Input, AddressInput, AddressOutput, Transaction, PrivateKey
from bitforge import networks

import termcolor # not a library dependency, obviously


def log(title, content):
    print(termcolor.colored(title + ":", 'green', attrs = ['bold']))
    print(content)
    print('')


PK_HEX = '21c601c0ae6dfcdcf622e6fe2be9153ed7ada0cc90a8a08475e57060e18c0791'

PREV_TX_ID = '4baa7551933fbf26158a619c3084ccdd5c0d81930b3e74a85a33ad26d13f1a55'
UTXO_INDEX = 0
AMOUNT     = 2000


privkey = PrivateKey.from_hex(PK_HEX, network = networks.testnet)
pubkey  = privkey.to_public_key()
address = pubkey.to_address()

i = AddressInput(PREV_TX_ID, UTXO_INDEX, address)
o = AddressOutput(AMOUNT, address)

t = Transaction([i], [o])

signed_transaction_hex = t.signed([ privkey ], 0).to_hex()


print('')
log("Private Key", privkey.to_hex())
log("Public Key", pubkey.to_hex())
log("Address", address.to_string())
log("Signed transaction hex", signed_transaction_hex)
