import json
from pytest import fixture, raises

from bitforge import encoding, network, privkey
from bitforge.privkey import PrivateKey


data = {
    'privkey_hex' : 'f04da984a7d553a0ac51b50bf92d2257d46f65286f2d5da5b83f8ccc114393a7',
    'privkey_bin' : '\xf0M\xa9\x84\xa7\xd5S\xa0\xacQ\xb5\x0b\xf9-"W\xd4oe(o-]\xa5\xb8?\x8c\xcc\x11C\x93\xa7',
    'pubkey': {
        'compress_hex'  : '02e9af68f090bdb18997b676103794e7ed43f9148e882f300d9173c7aac5d497d2',
        'uncompress_hex': '04e9af68f090bdb18997b676103794e7ed43f9148e882f300d9173c7aac5d497d26e4b866169626d83f6230cdc90e0c62a0ae7017579368cb870eb83dcaa1fec3a',
    },
    'wif' : {
        'live_compress'  : 'L5Gq3mntBKNR9inFjbzesJt2ziboDqjc2iK7Aj2qiy85goAXcjPV',
        'live_uncompress': '5Ke7or7mg3MFzFuPpiTf2tBCnFQk6dR9qsbTmoE74AYWcQ8FmJv',
        'test_compress'  : 'cVdpWgnjcP4gKAFX81onEdP6cwuCtHqJ6kTaH9VME5n5wYCzH5xU',
        'test_uncompress': '93QkPawKGGRPxKQgT4MZuUjARumTFnxMBpTQrRacPuHZPQdgS1D',
    },
    'address': {
        'live_compress'  : '1LjsiHFYCbXjCw4NCTR6AxakMqM3sUZqEf',
        'live_uncompress': '18zBfQUkeg9VZFWf53ApjtNgnJDhzdpMfR',
        'test_compress'  : 'n1Fq1LLX1cxyz3Xyv2PTzso5Dpwkk1s86J',
        'test_uncompress': 'moW8xTZjThakLMzGnc9CZob1eHpQsTNQN6',
    }
}


@fixture
def valid_wifs():
    with open('tests/data/valid_wifs.json') as f:
        return [ item for item in json.load(f) if item[2]['isPrivkey'] ]


@fixture
def invalid_wifs():
    with open('tests/data/invalid_wifs.json') as f:
        return [ item[0] for item in json.load(f) ]


@fixture
def invalid_exponents():
    return [-100, -1, 0, 2 ** 256 - 100, 2 ** 256, 2 ** 300]


@fixture
def valid_exponents():
    return [1, 2, 10000, 2 ** 255]


class TestPrivateKey(object):

    def test_generate_random_keys(self):

        k1 = PrivateKey.generate()
        k2 = PrivateKey.generate()
        assert k1.key.private_numbers() != k2.key.private_numbers()

    def test_from_secret_exponent(self, valid_exponents):

        for exponent in valid_exponents:
            k = PrivateKey.from_secret_exponent(exponent)
            assert k.key.private_numbers().private_value == exponent

    def test_from_invalid_secret_exponent(self, invalid_exponents):

        for exponent in invalid_exponents:
            with raises(privkey.InvalidExponent):
                PrivateKey.from_secret_exponent(exponent)

    def test_from_bytes(self):

        k = PrivateKey.from_bytes(data['privkey_bin'])

        assert k.compressed is True
        assert k.network is network.default
        assert k.to_bytes() == data['privkey_bin']

    def test_from_invalid_bytes(self):
        with raises(privkey.InvalidEncoding):
            PrivateKey.from_bytes('a')

        with raises(privkey.InvalidEncoding):
            PrivateKey.from_bytes('a' * 33)

    def test_from_wif_live_compress(self):
        k = PrivateKey.from_wif(data['wif']['live_compress'])

        assert k.compressed is True
        assert k.network is network.livenet
        assert k.to_wif() == data['wif']['live_compress']

    def test_from_wif_test_compress(self):
        k = PrivateKey.from_wif(data['wif']['test_compress'])

        assert k.compressed is True
        assert k.network is network.testnet
        assert k.to_wif() == data['wif']['test_compress']

    def test_from_wif_live_uncompress(self):
        k = PrivateKey.from_wif(data['wif']['live_uncompress'])

        assert k.compressed is False
        assert k.network is network.livenet
        assert k.to_wif() == data['wif']['live_uncompress']

    def test_from_wif_test_uncompress(self):
        k = PrivateKey.from_wif(data['wif']['test_uncompress'])

        assert k.compressed is False
        assert k.network is network.testnet
        assert k.to_wif() == data['wif']['test_uncompress']

    def test_from_invalid_wif(self):
        too_short = encoding.b2a_base58check('a')

        with raises(privkey.InvalidEncoding):
            PrivateKey.from_wif(too_short)

        too_long = encoding.b2a_base58check('a' * 30)

        with raises(privkey.InvalidEncoding):
            PrivateKey.from_wif(too_long)

        valid = encoding.a2b_base58check(PrivateKey.generate().to_wif())

        with raises(privkey.InvalidEncoding):
            PrivateKey.from_wif(encoding.b2a_base58check(valid[:-1] + 'a'))

        with raises(privkey.InvalidEncoding):
            PrivateKey.from_wif(encoding.b2a_base58check('a' + valid[1:]))

    def test_bitcoind_valid_wifs(self, valid_wifs):
        for wif, secret_hex, attrs in valid_wifs:
            secret = encoding.b2i_bigendian(encoding.a2b_hex(secret_hex))
            network_ = network.testnet if attrs['isTestnet'] else network.livenet
            compressed = attrs['isCompressed']

            k = PrivateKey.from_wif(wif)

            assert k.key.private_numbers().private_value == secret
            assert k.network is network_
            assert k.compressed == compressed

    def test_bitcoind_invalid_wifs(self, invalid_wifs):
        for invalid_wif in invalid_wifs:
            with raises(privkey.InvalidEncoding):
                PrivateKey.from_wif(invalid_wif)

    def test_roundtrip_wif(self):
        k1 = PrivateKey.generate()
        k2 = PrivateKey.from_wif(k1.to_wif())

        assert k1.key.private_numbers().private_value == k2.key.private_numbers().private_value
        assert k1.network is k2.network
        assert k1.compressed == k2.compressed

    # def test_to_pubkey_compressed(self):
    #     k = PrivateKey.from_wif(data['wif']['live_compress'])
    #     assert k.to_public_key().to_hex() == data['pubkey']['compress_hex']

    # def test_to_pubkey_compressed(self):
    #     k = PrivateKey.from_wif(data['wif']['live_uncompress'])
    #     assert k.to_public_key().to_hex() == data['pubkey']['uncompress_hex']

    # def test_to_address_live_compressed(self):
    #     k = PrivateKey.from_wif(data['wif']['live_compress'])
    #     assert k.to_address().to_string() == data['address']['live_compress']

    # def test_to_address_live_uncompressed(self):
    #     k = PrivateKey.from_wif(data['wif']['live_uncompress'])
    #     assert k.to_address().to_string() == data['address']['live_uncompress']

    # def test_to_address_test_compressed(self):
    #     k = PrivateKey.from_wif(data['wif']['test_compress'])
    #     assert k.to_address().to_string() == data['address']['test_compress']

    # def test_to_address_test_uncompressed(self):
    #     k = PrivateKey.from_wif(data['wif']['test_uncompress'])
    #     assert k.to_address().to_string() == data['address']['test_uncompress']
