from errors import *

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
