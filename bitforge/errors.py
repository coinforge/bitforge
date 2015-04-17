
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


class NumberError(BitforgeError):
    def prepare(self, number):
        self.number = number


class KeyValueError(BitforgeError):
    def prepare(self, key, value):
        self.key   = key
        self.value = value
