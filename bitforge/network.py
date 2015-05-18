import collections

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from bitforge import error


class Error(error.BitforgeError):
    pass


class UnknownNetwork(Error, error.KeyValueError):
    """No network with {key} matching '{value}'"""


class InvalidNetwork(Error, error.KeyValueError):
    """The network {key} '{value}' is already taken"""


class InvalidField(Error, error.StringError):
    """The field {string} is not unique and thus, not searchable"""


BaseNetwork = collections.namedtuple('Network', [

    # Descriptors
    'name',  # Main network name
    'aliases',  # All the network aliases

    # Cryptography parameters
    'curve',  # Elliptic curve used for the crypto
    'hash_function',  # Signature hashing function

    # Serialization magic numbers
    'pubkeyhash',
    'wif_prefix',  # Byte prefix used to identify the network in the WIF encoding
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

    UNIQUE_FIELDS = ['name', 'wif_prefix']

    _networks = []
    _networks_by_name = {}

    @classmethod
    def get(cls, name, raises=True):
        """Get a network by name or alias."""

        network = cls._networks_by_name.get(name, None)

        if raises and network is None:
            raise UnknownNetwork('name', name)

        return network

    @classmethod
    def get_by_field(cls, field, value, raises=True):
        """Get a network uniquely determined by a field."""

        if field not in cls.UNIQUE_FIELDS:
            if raises:
                raise InvalidField(field)
            return None

        for network in cls._networks:
            if getattr(network, field) == value:
                return network

        if raises:
            raise UnknownNetwork(field, value)

    def __new__(cls, **kwargs):
        network = super(Network, cls).__new__(cls, **kwargs)

        # Enforce all unique fields
        for other in cls._networks:
            for field in cls.UNIQUE_FIELDS:
                if getattr(other, field) == getattr(network, field):
                    raise InvalidNetwork(field, getattr(network, field))

        cls._networks.append(network)

        # Enforce uniqueness of the network aliases
        for name in [network.name] + network.aliases:
            if name in cls._networks_by_name:
                raise InvalidNetwork('name', name)
            cls._networks_by_name[name] = network

        return network

    def __repr__(self):
        return '<Network name: {}>'.format(self.name)

    def __str__(self):
        return self.name


testnet = Network(
    name = 'testnet',
    aliases = [],
    curve = ec.SECP256K1(),
    hash_function = hashes.SHA256,
    pubkeyhash = 111,
    wif_prefix = 239,
    scripthash = 196,
    hd_public_key = 0x043587cf,
    hd_private_key = 0x04358394,
    magic = 0x0b110907,
    port = 18333,
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
    curve = ec.SECP256K1(),
    hash_function = hashes.SHA256,
    pubkeyhash = 0x00,
    wif_prefix = 0x80,
    scripthash = 0x05,
    hd_public_key = 0x0488b21e,
    hd_private_key = 0x0488ade4,
    magic = 0xf9beb4d9,
    port = 8333,
    seeds = [
        'seed.bitcoin.sipa.be',
        'dnsseed.bluematt.me',
        'dnsseed.bitcoin.dashjr.org',
        'seed.bitcoinstats.com',
        'seed.bitnodes.io',
        'bitseed.xf2.org'
    ]
)
