from example_utils import log

from bitforge import networks
from bitforge import  AddressInput, AddressOutput, Transaction, PrivateKey


PK_HEX = '21c601c0ae6dfcdcf622e6fe2be9153ed7ada0cc90a8a08475e57060e18c0791'

PREV_TX_ID = 'da5360df3b0d4857cc1b785929dff052380c53f73017f258719de667f77e7dca'
UTXO_INDEX = 0
AMOUNT     = 11000


privkey = PrivateKey.from_hex(PK_HEX, network = networks.testnet)
pubkey  = privkey.to_public_key()
address = pubkey.to_address()


inputs  = [ AddressInput(PREV_TX_ID, UTXO_INDEX, address) ]
outputs = [ AddressOutput(AMOUNT - 1000, address) ]

tx = Transaction(inputs, outputs)

signed_transaction_hex = tx.sign([ privkey ], 0).to_hex()


print ''
log("Private Key", privkey.to_hex())
log("Public Key", pubkey.to_hex())
log("Address", address.to_string())
log("Signed transaction hex", signed_transaction_hex)
