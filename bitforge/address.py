import collections

import enum

from bitforge import encoding, error, network


class Type(enum.Enum):
    PublicKey = 'pubkey_hash'
    Script    = 'script_hash'


class Error(error.BitforgeError):
    pass


class InvalidEncoding(Error):
    pass


class InvalidHashLength(Error, error.StringError):
    "The address hash {string} should be 20 bytes long, not {length}"


class InvalidType(Error, error.ObjectError):
    "{object} is not a valid address type"


BaseAddress = collections.namedtuple('Address', [
    'hash',
    'type',
    'network',
])


class Address(BaseAddress):
    """Bitcoin address."""

    def __new__(cls, hash, type=Type.PublicKey, network=network.default):
        """TODO"""

        if not isinstance(type, Type):
            raise InvalidType(type)

        if len(hash) != 20:
            raise InvalidHashLength(hash)

        return super(Address, cls).__new__(cls, hash, type, network)

    @classmethod
    def from_string(cls, string):
        """TODO"""

        try:
            data = encoding.a2b_base58check(string)

        except encoding.InvalidEncoding as e:
            raise InvalidEncoding(e.message)

        return cls.from_bytes(data)

    @classmethod
    def from_bytes(cls, data):
        """TODO"""

        if len(data) != 21:
            raise InvalidEncoding('Invalid address length')

        type_, network_ = cls.classify_bytes(data)

        return cls(data[1:], type_, network_)

    @classmethod
    def from_hex(cls, string):
        """TODO"""

        try:
            data = encoding.a2b_hex(string)

        except encoding.InvalidEncoding as e:
            raise InvalidEncoding(e.message)

        return cls.from_bytes(data)

    @classmethod
    def classify_bytes(cls, data):
        """TODO"""

        data = bytearray(data)
        version = data[0]

        network_ = network.Network.get_by_field('pubkey_hash_prefix', version, raises=False)
        if network_ is not None:
            return (Type.PublicKey, network_)

        network_ = network.Network.get_by_field('script_hash_prefix', version, raises=False)
        if network_ is not None:
            return (Type.Script, network_)

        raise InvalidEncoding('Invalid version number')

    @classmethod
    def from_public_key(cls, pubkey):
        """TODO"""

        return pubkey.address()

    def to_bytes(self):
        """TODO"""

        version = getattr(self.network, self.type.value)
        return chr(version) + self.hash

    def to_string(self):
        """TODO"""

        return encoding.b2a_base58check(self.to_bytes())

    def to_hex(self):
        """TODO"""

        return encoding.b2a_hex(self.to_bytes())

    # TODO: all keys should be from the same network
    # @classmethod
    # def from_public_keys(pubkeys, threshold):
    #     return Address.from_script(
    #         Script.buildMultisigOut(pubkeys, threshold),
    #         pubkeys[0].network
    #     )

    # @classmethod
    # def from_script(script, network = networks.default):
    #     if not isinstance(script, Script):
    #         raise ValueError('Expected instance of Script, not %s' % script)
    #
    #     return Address(
    #         raw     = utils.encoding.hash160(script.to_bytes()),
    #         type    = Address.Type.Script,
    #         network = network
    #     )

    def __repr__(self):
        return "<Address: %s, type: %s, network: %s>" % (self.to_string(), self.type.name, self.network.name)
