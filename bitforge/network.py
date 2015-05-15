from collections import namedtuple
from cryptography.hazmat.primitives.asymmetric import ec
from errors import BitforgeError, KeyValueError, StringError


# TODO: document these fields
# TODO: which should be unique? It should be enforced
BaseNetwork = namedtuple('Network', [
    # Descriptors
    'name',
    'aliases',
    # Cryptography parameters
    'curve',
    # Serialization magic numbers
    'pubkeyhash',
    'wif_prefix',
    'scripthash',
    'hd_public_key',
    'hd_private_key',
    'magic',
    # Network parameters
    'port',
    'seeds',
])


class Network(BaseNetwork):
    """Parameters of a Bitcoin-compatible network."""

    class Error(BitforgeError):
        pass

    class UnknownNetwork(Error, KeyValueError):
        """No network with '{key}' matching '{value}'"""

    class MultipleNetworks(Error, KeyValueError):
        """Multiple networks with '{key}' matching '{value}'"""

    class ExistingNetworkName(Error, StringError):
        """Network name '{string}' already taken"""

    _networks = {}

    @classmethod
    def get(cls, name, raises=True):
        """Get a network by name or alias."""

        network = cls._networks.get(name, None)

        if raises and network is None:
            raise Network.UnknownNetwork('name', name)

        return network

    # TODO: discuss if this method should exist at all
    @classmethod
    def get_by_field(cls, field, value, raises=True):
        """Get a network uniquely determined by a field."""

        matches = []

        for network in cls._networks:
            if getattr(network, field, None) == value:
                matches.append(network)

        if raises and len(matches) == 0:
            raise Network.UnknownNetwork(field, value)

        if raises and len(matches) > 1:
            raise Network.MultipleNetworks(field, value)

        if len(matches) == 1:
            return matches[0]

    def __new__(cls, **kwargs):
        network = super(Network, cls).__new__(cls, **kwargs)
        network._register()
        return network

    def _register(self):
        """Register a network by its unique name and aliases."""

        for name in [self.name] + self.aliases:
            if name in self._networks:
                raise Network.ExistingNetworkName(name)
            self._networks[name] = self


testnet = Network(
    name = 'testnet',
    aliases = [],

    curve = ec.SECP256K1,

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
    aliases = ['mainnet', 'default'],

    curve = ec.SECP256K1,

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
