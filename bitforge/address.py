from enum import Enum
import binascii, collections
import networks, utils
# class: Address
# new Address(data, network, [type])
# Address.PayToPublicKeyHash
# Address.PayToScriptHash

# Address.createMultisig(publicKeys, threshold, network)

# Address.fromPublicKey(data, network)
# Address.fromPublicKeyHash(hash, network)
# Address.fromScriptHash(hash, network)
# Address.fromScript(script, network)

# Address.payingTo(script, network)

# Address.isValid(data, network, type)
# address.isPayToPublicKeyHash()
# address.isPayToScriptHash()

# address.toBytes()
# Address.fromBytes(buffer, network, [type])

# address.toDict()
# Address.fromDict(json)

# address.toString()
# Address.fromString(str, network, [type])

# TODO: add validations to EVERYTHING!!!!!
# TODO: s/hash/something
BaseAddress = collections.namedtuple('Address', ['hash_bytes', 'network', 'type'])

class Address(BaseAddress):

    # TODO: s/hash/sth
    class Type(Enum):
        PublicKeyHash = 'pubkeyhash';
        ScriptHash    = 'scripthash';


    # TODO: ...
    # XXX: type shouldn't be None!
    def __new__(cls, hash_bytes, network = networks.default, type = None):
        network = networks.find(network)

        # check arguments

        return super(Address, cls).__new__(cls, hash_bytes, network, type)

    @staticmethod
    def fromPublicKey(pubkey):
        hash_bytes = utils.encoding.hash160(pubkey.toBytes())
        return Address(hash_bytes, pubkey.network, Address.Type.PublicKeyHash)

    # TODO: all keys should be from the same network
    # TODO: s/create/fromBLEBLE
    @staticmethod
    def createMultisig(pubkeys, threshold):
        from script import Script
        return Address.payingTo(Script.buildMultisigOut(pubkeys, threshold), pubkeys[0].network)

    # TODO: s/payingTo/fromScript
    @staticmethod
    def payingTo(script, network = networks.default):
        from script import Script
        if not isinstance(script, Script):
            raise ValueError('%s script must be instnace of Script', script)

        return Address.fromScriptHash(utils.encoding.hash160(script.toBytes()), network)

    # TODO: merge with ^
    @staticmethod
    def fromScriptHash(hash_bytes, network = networks.default):
        return Address(hash_bytes, network, Address.Type.ScriptHash)

    # TODO: toString, toFormat, blabla
    def __str__(self):
        prefix = getattr(self.network, self.type.value)
        return utils.encoding.hash160_sec_to_bitcoin_address(self.hash_bytes, chr(prefix))

    def __repr__(self):
        return "<Address: %s, type: %s, network: %s>" % (str(self), self.type.name, self.network.name)
