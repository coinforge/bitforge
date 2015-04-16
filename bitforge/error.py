
class BitforgeError(Exception):
    def __init__(self, *args, **kwargs):
        self.prepare(*args, **kwargs)
        self.message = self.__doc__.format(**self.__dict__)

    def prepare(self):
        pass

    def __str__(self):
        return self.message


class StringError(BitforgeError):
    def prepare(self, string):
        self.string = repr(string)
        self.length = len(string)


class InvalidBase58(StringError):
    "The string {string} is not base58-encoded"


class UnknownNetwork(BitforgeError):
    "No network with an attribute '{attr}' of value {value}"

    def prepare(self, attr, value):
        self.attr  = attr
        self.value = value


class PrivateKeyError(BitforgeError):
    pass


class InvalidSecret(PrivateKeyError):
    "Invalid secret for PrivateKey: {secret}"

    def prepare(self, secret):
        self.secret = secret


class InvalidKeyLength(PrivateKeyError, StringError):
    "The buffer {string} should be 33 (uncompressed) or 34 (compressed) bytes long, not {length}"


class InvalidCompressionByte(PrivateKeyError, StringError):
    "The length of the WIF {string} suggests it's compressed, but it doesn't end in '\1'"
