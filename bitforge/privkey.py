import random, struct, binascii, collections
import networks, ecdsa
from pubkey import PublicKey
# class: PrivateKey
# new PrivateKey(data, network)

# PrivateKey.fromHex()
# PrivateKey.toHex()

# PrivateKey.fromBytes(arg, network)
# PrivateKey.toBytes(arg, network)

# PrivateKey.isValid(data, [network])
# privateKey.toPublicKey()
# privateKey.toAddress([network])

# privateKey.toDict()
# PrivateKey.fromDict(obj)



rng     = random.SystemRandom()
KEY_MAX = ecdsa.generator_secp256k1.order()

def randomKeyNumber():
    return rng.randint(1, KEY_MAX - 1)


BasePrivateKey = collections.namedtuple('PrivateKey', ['number', 'network', 'compressed'])

class PrivateKey(BasePrivateKey):
    def __new__(cls, number = None, network = networks.default, compressed = True):
        # Step 1: find the network. May raise UnknownNetwork.
        network = networks.find(network)

        # Step 2: convert or generate the internal representation.
        if number is None:
            number = randomKeyNumber()

        # Step 3: build the immutable tuple.
        return super(PrivateKey, cls).__new__(cls, number, network, compressed)


    # @staticmethod
    # def fromArray(array, network = networks.default):
    #     number  = ecdsa.intbytes.to_bytes_32(array)
    #     network = networks.find(network)
    #
    #     return PrivateKey(number, network)

    @staticmethod
    def fromWIF(wif):
        data = ecdsa.encoding.a2b_hashed_base58(wif)
        network = networks.find(ord(data[0]), 'wif_prefix')
        compressed = len(data) > 33

        if compressed:
            data = data[:-1]   

        number = ecdsa.encoding.from_bytes_32(data[1:])
        return PrivateKey(number, network, compressed)

    def toBytes(self):
        return ecdsa.encoding.to_bytes_32(self.number)

    def toHex(self):
        return binascii.hexlify(self.toBytes())

    def toWIF(self):
        bytes = chr(self.network.wif_prefix) + self.toBytes()

        if self.compressed:
            bytes += '\1'

        return ecdsa.encoding.b2a_hashed_base58(bytes)

    @property
    def publickey(self):
        return PublicKey.fromPrivateKey(self)

    def __repr__(self):
        return "<PrivateKey: %s, network: %s>" % (self.toHex(), self.network.name)
