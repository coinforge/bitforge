import random, struct, binascii, collections
import networks, ecdsa
# class: PublicKey
# new PublicKey(data, extra)

# publicKey.toBytes()
# publicKey.fromBytes()

# PublicKey.fromPoint(point, [compressed])
# PublicKey.fromX(odd, x)

# PublicKey.isValid(data)
# publicKey.toAddress(network)

# PublicKey.fromDict(json)
# publicKey.toDict()
# publicKey._getID()

BasePublicKey = collections.namedtuple('PublicKey', ['point', 'network', 'compressed'])

class PublicKey(BasePublicKey):
    def __new__(cls, point, network = networks.default, compressed = True):
        network = networks.find(network)

        # check arguments

        return super(PublicKey, cls).__new__(cls, point, network, compressed)

    @staticmethod
    def fromPrivateKey(privkey):
        point = ecdsa.public_pair_for_secret_exponent(ecdsa.generator_secp256k1, privkey.number)
        return PublicKey(point, privkey.network, privkey.compressed)

    @staticmethod
    def fromBytes(bytes, network = networks.default):
        point = ecdsa.encoding.sec_to_public_pair(bytes)
        compressed = ecdsa.encoding.is_sec_compressed(bytes)
        return PublicKey(point, network, compressed)

    @staticmethod
    def fromHex(hex, network = networks.default):
        bytes = binascii.unhexlify(hex)
        return PublicKey.fromBytes(bytes, network)

    def toBytes(self):
        return ecdsa.encoding.public_pair_to_sec(self.point, self.compressed)

    def toHex(self):
        return binascii.hexlify(self.toBytes())

    def __repr__(self):
        return "<PublicKey: %s, network: %s>" % (self.toHex(), self.network.name)
