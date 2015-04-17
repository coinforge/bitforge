
class BitforgeError(Exception):
    def __init__(self, *args, **kwargs):
        self.cause = kwargs.pop('cause', None)
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


class InvalidBase58h(StringError):
    "The string {string} is not valid base58/check"


class InvalidHex(StringError):
    "The string {string} is not valid hexadecimal"


class PrivateKeyError(BitforgeError):
    "PrivateKey integrity error"


class UnknownNetwork(PrivateKeyError):
    "No network with an attribute '{attr}' of value {value}"

    def prepare(self, attr, value):
        self.attr  = attr
        self.value = value


class InvalidSecret(PrivateKeyError):
    "Invalid secret for PrivateKey: {secret}"

    def prepare(self, secret):
        self.secret = secret


class InvalidWifLength(PrivateKeyError, StringError):
    "The WIF {string} should be 33 (uncompressed) or 34 (compressed) bytes long, not {length}"


class InvalidSecretLength(PrivateKeyError, StringError):
    "The secret {string} should be 32 bytes long, not {length}"


class InvalidCompressionByte(PrivateKeyError, StringError):
    "The length of the WIF {string} suggests it's compressed, but it doesn't end in '\1'"
