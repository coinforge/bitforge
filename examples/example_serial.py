from bitforge.encoding import *
from bitforge import Input, Output, AddressInput, AddressOutput, Transaction, PrivateKey
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

i = AddressInput.create(PREV_TX_ID, UTXO_INDEX, address)
o = AddressOutput.create(AMOUNT, address)

t1 = Transaction([i], [o])
t2 = Transaction.from_bytes(t1.to_bytes())

log("Transaction hex 1", t1.to_hex())
log("Transaction hex 2", t2.to_hex())
print('equal', t1 == t2)
# __import__('IPython').embed()
