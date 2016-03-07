from bitforge.encoding import *
from bitforge import Address, Script, Input, MultisigInput, AddressInput, AddressOutput, MultisigOutput, Transaction, PrivateKey
from bitforge import networks

import termcolor # not a library dependency, obviously


def log(title, content):
    print termcolor.colored(title + ":", 'green', attrs = ['bold'])
    print content
    print ''



PK_HEX = '21c601c0ae6dfcdcf622e6fe2be9153ed7ada0cc90a8a08475e57060e18c0791'

MULTISIG_PKS_HEX = [
    'd0e44c9e1ab05b194ec537f52d6048aef4eb32bea0bc815ad62bd303bd25539b',
    '5302762f5ddea3c6311e670454b9400682901b0acdb5b6098973ec89d7315b0a',
    '0a8653b645ca225735c193ae3e91d231fc9cbb74756223a140699d7368d5ece2'
]

MIN_SIGS   = 2

R2M_TX_ID      = '2d3e2b3714efa2ab9ecb721662f4941b4a9a801868489df8ce60e717102715c4'
R2M_UTXO_INDEX = 0
R2M_AMOUNT     = 16000

M2R_TX_ID      = '1ac197a4b49f454adeb89cb51c266627ac7da4197f999e2f5cdf219144596209'
M2R_UTXO_INDEX = 0
M2R_AMOUNT     = R2M_AMOUNT - 1000


privkey = PrivateKey.from_hex(PK_HEX, network = networks.testnet)
pubkey  = privkey.to_public_key()
address = pubkey.to_address()

multisig_privkeys = [ PrivateKey.from_hex(pk_hex, network = networks.testnet) for pk_hex in MULTISIG_PKS_HEX ]
multisig_pubkeys  = [ pk.to_public_key() for pk in multisig_privkeys ]
multisig_address  = Address.from_script(Script.redeem_multisig(multisig_pubkeys, MIN_SIGS))


def from_regular_to_multisig():
    i = AddressInput(R2M_TX_ID, R2M_UTXO_INDEX, address)
    o = MultisigOutput(R2M_AMOUNT, multisig_pubkeys, MIN_SIGS)

    return Transaction([i], [o])


def from_multisig_to_regular():
    i = MultisigInput(M2R_TX_ID, M2R_UTXO_INDEX, multisig_pubkeys, MIN_SIGS)
    o = AddressOutput(M2R_AMOUNT - 1000, address)

    return Transaction([i], [o])


print ''
log("Regular private Key", privkey.to_hex())
log("Regular public Key", pubkey.to_hex())
log("Regular address", address.to_string())

log("Multisig private keys", '\n'.join(privkey.to_hex() for privkey in multisig_privkeys))
log("Multisig public keys", '\n'.join(pubkey.to_hex() for pubkey in multisig_pubkeys))
log("Multisig address", multisig_address.to_string())

log("Regular to multisig transaction hex", from_regular_to_multisig().signed([ privkey ], 0).to_hex())
log("Multisig to regular transaction hex", from_multisig_to_regular().signed(multisig_privkeys[:MIN_SIGS], 0).to_hex())
