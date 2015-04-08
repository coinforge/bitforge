import random, struct, binascii, collections
import networks, ecdsa
# class: PrivateKey
# new PrivateKey(data, network)
# PrivateKey.fromString
# privateKey._classifyArguments(data, network)
# PrivateKey.fromJSON(json)
# PrivateKey.fromBuffer(arg, network)
# PrivateKey.fromRandom([network])
# PrivateKey.getValidationError(data, [network])
# PrivateKey.isValid(data, [network])
# privateKey.toString()
# privateKey.toWIF()
# privateKey.toBigNumber()
# privateKey.toBuffer()
# privateKey.toPublicKey()
# privateKey.toAddress([network])
# privateKey.toObject()
# privateKey.inspect()


rng     = random.SystemRandom()
KEY_MAX = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

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
    #
    #
    def toBytes(self):
        return ecdsa.encoding.to_bytes_32(self.number)

    def toWIF(self):
        bytes = chr(self.network.wif_prefix) + self.toBytes()

        if self.compressed:
            bytes += '\1'

        return ecdsa.encoding.b2a_hashed_base58(bytes)

    def __repr__(self):
        return "PrivateKey(%s @%s)" % (self.number, self.network.name)



p = PrivateKey(10)
print p
print p.toWIF()
# print PrivateKey.fromArray([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0])
