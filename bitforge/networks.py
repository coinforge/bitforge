import sys
from collections import namedtuple
import error


# Network objects are immutable, and should be unique
Network = namedtuple('Network', [
    'name',

    'pubkeyhash',
    'wif_prefix',
    'scripthash',
    'hd_public_key',
    'hd_private_key',
    'magic',

    'port',
    'seeds'
])


testnet = Network(
    name = 'testnet',

    pubkeyhash = 111,
    wif_prefix = 239,
    scripthash = 196,
    hd_public_key   = 0x043587cf,
    hd_private_key  = 0x04358394,
    magic      = 0x0b110907,

    port  = 18333,
    seeds = [
        'testnet-seed.bitcoin.petertodd.org',
        'testnet-seed.bluematt.me',
        'testnet-seed.alexykot.me',
        'testnet-seed.bitcoin.schildbach.de'
    ]
)

default = livenet = Network(
  name = 'livenet',

  pubkeyhash = 0x00,
  wif_prefix = 0x80,
  scripthash = 0x05,
  hd_public_key    =  0x0488b21e,
  hd_private_key   = 0x0488ade4,
  magic      = 0xf9beb4d9,

  port  = 8333,
  seeds = [
    'seed.bitcoin.sipa.be',
    'dnsseed.bluematt.me',
    'dnsseed.bitcoin.dashjr.org',
    'seed.bitcoinstats.com',
    'seed.bitnodes.io',
    'bitseed.xf2.org'
  ]
)

_networks = [livenet, testnet]

def find(value, attr = 'name'):
    if isinstance(value, Network):
        return value

    try:
      for network in _networks:
        if getattr(network, attr) == value:
          return network

    except AttributeError:
      pass # networks don't have this attribute!

    raise error.UnknownNetwork(attr, value)
