import json
from pytest import raises, fixture, fail

from bitforge import networks
from bitforge.encoding import *
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


class TestPrivateKey:

    def test_from_random(self):
        k1, k2 = PrivateKey(), PrivateKey()
        assert k1.secret != k2.secret


    def test_invalid_secret(self):
        with raises(PrivateKey.InvalidSecret): PrivateKey(-1)
        with raises(PrivateKey.InvalidSecret): PrivateKey(10 ** 100)


    def test_invalid_network(self):
        with raises(PrivateKey.UnknownNetwork):
            PrivateKey(network = -1)


    def test_from_hex(self):
        k = PrivateKey.from_hex(data['privkey_hex'])

        assert k.to_hex() == data['privkey_hex']
        assert k.to_bytes() == data['privkey_bin']

        assert k.compressed is True
        assert k.network is networks.default


    def test_from_invalid_hex(self):
        with raises(PrivateKey.InvalidHex): PrivateKey.from_hex('a')
        with raises(PrivateKey.InvalidHex): PrivateKey.from_hex('a@')


    def test_from_bytes(self):
        k = PrivateKey.from_bytes(data['privkey_bin'])

        assert k.to_hex() == data['privkey_hex']
        assert k.to_bytes() == data['privkey_bin']

        assert k.compressed is True
        assert k.network is networks.default


    def test_from_invalid_bytes(self):
        with raises(PrivateKey.InvalidBinaryLength):
            PrivateKey.from_bytes('a')

        with raises(PrivateKey.InvalidBinaryLength):
            PrivateKey.from_bytes('a' * 33)


    def test_from_wif_live_compress(self):
        k = PrivateKey.from_wif(data['wif']['live_compress'])

        assert k.compressed is True
        assert k.network is networks.livenet
        assert k.to_wif() == data['wif']['live_compress']


    def test_from_wif_test_compress(self):
        k = PrivateKey.from_wif(data['wif']['test_compress'])

        assert k.compressed is True
        assert k.network is networks.testnet
        assert k.to_wif() == data['wif']['test_compress']


    def test_from_wif_live_uncompress(self):
        k = PrivateKey.from_wif(data['wif']['live_uncompress'])

        assert k.compressed is False
        assert k.network is networks.livenet
        assert k.to_wif() == data['wif']['live_uncompress']


    def test_from_wif_test_uncompress(self):
        k = PrivateKey.from_wif(data['wif']['test_uncompress'])

        assert k.compressed is False
        assert k.network is networks.testnet
        assert k.to_wif() == data['wif']['test_uncompress']


    def test_from_invalid_wif(self):
        too_short = encode_base58h('a')
        too_long  = encode_base58h('a' * 30)

        with raises(PrivateKey.InvalidWifLength): PrivateKey.from_wif(too_short)
        with raises(PrivateKey.InvalidWifLength): PrivateKey.from_wif(too_long)

        valid = decode_base58h(PrivateKey().to_wif())

        with raises(PrivateKey.InvalidCompressionByte):
            PrivateKey.from_wif(encode_base58h(valid[:-1] + 'a'))

        with raises(PrivateKey.UnknownNetwork):
            PrivateKey.from_wif(encode_base58h('a' + valid[1:]))


    def test_bitcoind_valid_wifs(self, valid_wifs):
        for wif, secret_hex, attrs in valid_wifs:
            secret     = decode_int(decode_hex(secret_hex))
            network    = networks.testnet if attrs['isTestnet'] else networks.livenet
            compressed = attrs['isCompressed']

            k = PrivateKey.from_wif(wif)

            assert k.secret == secret
            assert k.network is network
            assert k.compressed == compressed


    def test_bitcoind_invalid_wifs(self, invalid_wifs):
        for invalid_wif in invalid_wifs:
            with raises(PrivateKey.Error):
                PrivateKey.from_wif(invalid_wif)


    def test_to_pubkey_compressed(self):
        k = PrivateKey.from_wif(data['wif']['live_compress'])
        assert k.to_public_key().to_hex() == data['pubkey']['compress_hex']


    def test_to_pubkey_compressed(self):
        k = PrivateKey.from_wif(data['wif']['live_uncompress'])
        assert k.to_public_key().to_hex() == data['pubkey']['uncompress_hex']


    def test_to_address_live_compressed(self):
        k = PrivateKey.from_wif(data['wif']['live_compress'])
        assert k.to_address().to_string() == data['address']['live_compress']


    def test_to_address_live_uncompressed(self):
        k = PrivateKey.from_wif(data['wif']['live_uncompress'])
        assert k.to_address().to_string() == data['address']['live_uncompress']


    def test_to_address_test_compressed(self):
        k = PrivateKey.from_wif(data['wif']['test_compress'])
        assert k.to_address().to_string() == data['address']['test_compress']


    def test_to_address_test_uncompressed(self):
        k = PrivateKey.from_wif(data['wif']['test_uncompress'])
        assert k.to_address().to_string() == data['address']['test_uncompress']


    def test_roundtrip_wif(self):
        k1 = PrivateKey()
        k2 = PrivateKey.from_wif(k1.to_wif())

        assert k1.secret == k2.secret
        assert k1.network is k2.network
        assert k1.compressed == k2.compressed
