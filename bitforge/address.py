import binascii, collections
import networks, utils
from enum import Enum
# from script import Script

# TODO: add validations to EVERYTHING!!!!!
# TODO: s/hash/something
BaseAddress = collections.namedtuple('Address', ['raw', 'network', 'type'])

class Address(BaseAddress):

    class Type(Enum):
        PublicKey = 'pubkeyhash';
        Script    = 'scripthash';

    # XXX: type shouldn't be None!
    # TODO: check arguments
    def __new__(cls, raw, network = networks.default, type = Type.PublicKey):
        network = networks.find(network) # may raise UnknownNetwork

        return super(Address, cls).__new__(cls, raw, network, type)

    @staticmethod
    def from_public_key(pubkey):
        raw = utils.encoding.hash160(pubkey.to_bytes())

        return Address(raw, pubkey.network, Address.Type.PublicKey)

    # TODO: all keys should be from the same network
    @staticmethod
    def from_public_keys(pubkeys, threshold):
        return Address.from_script(
            Script.buildMultisigOut(pubkeys, threshold),
            pubkeys[0].network
        )

    @staticmethod
    def from_script(script, network = networks.default):
        if not isinstance(script, Script):
            raise ValueError('Expected instance of Script, not %s' % script)

        return Address(
            raw     = utils.encoding.hash160(script.to_bytes()),
            type    = Address.Type.Script,
            network = network
        )

    # TODO: toString, toFormat, blabla
    def to_string(self):
        prefix = getattr(self.network, self.type.value)
        return utils.encoding.hash160_sec_to_bitcoin_address(self.raw, chr(prefix))

    def __repr__(self):
        return "<Address: %s, type: %s, network: %s>" % (self.to_string(), self.type.name, self.network.name)
