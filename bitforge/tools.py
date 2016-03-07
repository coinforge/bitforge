from errors import *
from encoding import *


class Buffer(bytearray):

    class Error(BitforgeError):
        pass

    class InsufficientData(Error):
        "Attempted to read {requested} bytes, but buffer only has {remaining}"

        def prepare(self, remaining, requested):
            self.remaining = remaining
            self.requested = requested


    def read(self, amount):
        if len(self) < amount:
            raise Buffer.InsufficientData(len(self), amount)

        ret = str(self[:amount])
        del self[:amount]
        return ret

    def write(self, data):
        self.extend(data)


def enforce(object, predicate, ExceptionClass):
    if not predicate(object):
        raise ExceptionClass(object)


def enforce_all(objects, predicate, ExceptionClass):
    for object in objects:
        enforce(object, predicate, ExceptionClass)


def instance_of(Class):
    def is_instance_of(object):
        return isinstance(object, Class)

    return is_instance_of


# def has_length(min, max, ExceptionClass):
#     def object_has_length(object):
#         length = len(object)
#         return (min is None or length >= min) and (max is None or length <= max)
#
#     return object_has_length
