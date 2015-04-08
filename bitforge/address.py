from enum import Enum
import binascii, collections
import networks, ecdsa
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


BaseAddress = collections.namedtuple('Address', ['hash_bytes', 'network', 'type'])

class Address(BaseAddress):

    class Type(Enum):
        PublicKeyHash = 'pubkeyhash';
        ScriptHash = 'scripthash';

    def __new__(cls, hash_bytes, network = networks.default, type = None):
        network = networks.find(network)

        # check arguments

        return super(Address, cls).__new__(cls, hash_bytes, network, type)

    @staticmethod
    def fromPublicKey(pubkey, network = networks.default):
        hash_bytes = ecdsa.encoding.hash160(pubkey.toBytes())
        return Address(hash_bytes, network, Address.Type.PublicKeyHash)

    def __str__(self):
        prefix = chr(self.network.pubkeyhash)
        return ecdsa.encoding.hash160_sec_to_bitcoin_address(self.hash_bytes, prefix)

    def __repr__(self):
        return "<Address: %s, type: %s, network: %s>" % (str(self), self.type.name, self.network.name)
