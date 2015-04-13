import bitforge.networks
from bitforge.privkey import PrivateKey
from bitforge.pubkey import PublicKey


data = {
    'privkey_hex': 'd862dc70f3a40b52e9ed3567b073e32dc543f3b51c9eae8f3ac3e95a05af6b65',
    'pubkey_bin' : '\x03\xb8\x05\x17K\xd4\x96\xb2u\xe7\x11\xd5\xa9\xf1\xbc\xba\xa4\xbb\xa1\xa7qv\xdb\xdb_\xdd\x8bv\x9d\xa6*6\xa9',
    'pubkey_hex' : {
        'compress'  : '03b805174bd496b275e711d5a9f1bcbaa4bba1a77176dbdb5fdd8b769da62a36a9',
        'uncompress': '04b805174bd496b275e711d5a9f1bcbaa4bba1a77176dbdb5fdd8b769da62a36a9c3dfa7c8ccb509f9a66efd6d8d1db6b25aa7c100476154b6303d76c28eda099b',
    },
    'address': {
        'live_compress'  : '1N8FRuC7P1ZtLfkjrvGrCTGkZXuLk4p8rE',
        'live_uncompress': '1MGu43MAwpDnKb4d3xmNZvupLwk6iaaQay',
        'test_compress'  : 'n2eCixH6C3197nEMaVFE2NV5RXW3cazW4Q',
        'test_uncompress': 'n1nrM6S9kqf36hYEmXjkPr89CwLobCH2nR',
    }
}

class TestPublicKey:
    def test_from_private_key_live_compress(self):
        priv = PrivateKey.from_hex(data['privkey_hex'], bitforge.networks.livenet, True)
        pub  = PublicKey.from_private_key(priv)

        assert pub.network is priv.network
        assert pub.compressed is priv.compressed
        assert pub.to_hex() == data['pubkey_hex']['compress']

    def test_from_private_key_live_uncompress(self):
        priv = PrivateKey.from_hex(data['privkey_hex'], bitforge.networks.livenet, False)
        pub  = PublicKey.from_private_key(priv)

        assert pub.network is priv.network
        assert pub.compressed is priv.compressed
        assert pub.to_hex() == data['pubkey_hex']['uncompress']

    def test_from_private_key_test_compress(self):
        priv = PrivateKey.from_hex(data['privkey_hex'], bitforge.networks.testnet, True)
        pub  = PublicKey.from_private_key(priv)

        assert pub.network is priv.network
        assert pub.compressed is priv.compressed
        assert pub.to_hex() == data['pubkey_hex']['compress']

    def test_from_private_key_test_uncompress(self):
        priv = PrivateKey.from_hex(data['privkey_hex'], bitforge.networks.testnet, False)
        pub  = PublicKey.from_private_key(priv)

        assert pub.network is priv.network
        assert pub.compressed is priv.compressed
        assert pub.to_hex() == data['pubkey_hex']['uncompress']

    def test_from_hex_compress(self):
        pk = PublicKey.from_hex(data['pubkey_hex']['compress'])
        assert pk.to_hex() == data['pubkey_hex']['compress']

        assert pk.compressed == True
        assert pk.network == bitforge.networks.default

    def test_from_hex_uncompress(self):
        pk = PublicKey.from_hex(data['pubkey_hex']['uncompress'])
        assert pk.to_hex() == data['pubkey_hex']['uncompress']

        assert pk.compressed == False
        assert pk.network == bitforge.networks.default

    def test_from_bytes(self):
        pk = PublicKey.from_bytes(data['pubkey_bin'])
        assert pk.to_bytes() == data['pubkey_bin']

        assert pk.compressed == True
        assert pk.network == bitforge.networks.default

    def test_to_address_live_compress(self):
        pk = PublicKey.from_hex(data['pubkey_hex']['compress'], bitforge.networks.livenet)
        assert pk.to_address().to_string() == data['address']['live_compress']

    def test_to_address_live_uncompress(self):
        pk = PublicKey.from_hex(data['pubkey_hex']['uncompress'], bitforge.networks.livenet)
        assert pk.to_address().to_string() == data['address']['live_uncompress']

    def test_to_address_test_compress(self):
        pk = PublicKey.from_hex(data['pubkey_hex']['compress'], bitforge.networks.testnet)
        assert pk.to_address().to_string() == data['address']['test_compress']

    def test_to_address_test_uncompress(self):
        pk = PublicKey.from_hex(data['pubkey_hex']['uncompress'], bitforge.networks.testnet)
        assert pk.to_address().to_string() == data['address']['test_uncompress']
