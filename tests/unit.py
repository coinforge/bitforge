from bitforge.unit import Unit


class TestUnit:

    def test_btc_accessors(self):
        u = Unit(btc = 1.2)
        assert u.btc == 1.2
        assert u.mbtc == 1200
        assert u.bits == 1200000
        assert u.satoshis == 120000000

    def test_btc_conversion(self):
        u = Unit(btc = 1.3)
        assert u.mbtc == 1300
        assert u.bits == 1300000
        assert u.satoshis == 130000000

        u = Unit(mbtc = 1.3)
        assert u.btc == 0.0013
        assert u.bits == 1300
        assert u.satoshis == 130000

        u = Unit(bits = 1.3)
        assert u.btc == 0.0000013
        assert u.mbtc == 0.0013
        assert u.satoshis == 130

        u = Unit(satoshis = 3)
        assert u.btc == 0.00000003
        assert u.mbtc == 0.00003
        assert u.bits == 0.03

    # TODO: Review presition
    # def test_unit_rates(self):
    #     u = Unit.from_fiat(1.3, 350)
    #     assert u.at_rate(350) == 1.3

    #     u = Unit(btc = 0.0123)
    #     assert u.at_rate(10) == 0.12

    def test_repr(self):
        u = Unit(btc = 1.3)
        assert repr(u) == '<Unit: 130000000 satoshis>'
