
class Unit(object):

    btc = 1e8
    mbtc = 1e5
    bits = 1e2
    satoshis = 1.0

    @staticmethod
    def from_fiat(value, rate):
        return Unit(btc = value / float(rate))

    def __init__(self, satoshis = None, bits = None, mbtc = None, btc = None):
        if satoshis is not None:
            self._set_values(satoshis)
        elif bits is not None:
            self._set_values(bits * Unit.bits)
        elif mbtc is not None:
            self._set_values(mbtc * Unit.mbtc)
        elif btc is not None:
            self._set_values(btc * Unit.btc)
        else:
            raise ValueError('Invalid arguments')

    def _set_values(self, satoshis):
        self.satoshis = int(satoshis)
        self.bits = self.satoshis / Unit.bits
        self.mbtc = self.satoshis / Unit.mbtc
        self.btc = self.satoshis / Unit.btc

    def at_rate(self, rate):
        return self.btc * rate

    def __str__(self):
        return '%s satoshis' % self.satoshis

    def __repr__(self):
        return '<Unit: %s>' % str(self)
