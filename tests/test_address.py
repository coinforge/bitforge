from __future__ import unicode_literals
import json

from pytest import raises, fixture, fail

from bitforge import networks, Address, PublicKey
from bitforge.encoding import *


data = {
    'base58h': 'mz7Rb837TrRMBxSNV8ZqRysS1JCDPWFLCc',
    'hex'    : '6fcbf730e06e5f8e4fc44f071d436a4660ddde3e47',
    'phash'  : 'cbf730e06e5f8e4fc44f071d436a4660ddde3e47',
    'network': networks.testnet,
    'type'   : Address.Type.PublicKey,
    'pubkey' : [
        2505267213527803793801554682227237457256110293342017361806815033635284562140,
        62983861414933912325775225572939498310844638563302563929329670771752596415141
    ]
}


def read_addr_fixture_info(info):
    string_b58h, string_hex, meta = info

    network = networks.testnet if meta['isTestnet'] else networks.livenet
    type    = Address.Type.PublicKey if meta['addrType'] == 'pubkey' else Address.Type.Script

    return (string_b58h, string_hex, network, type)


@fixture
def valid_addresses():
    with open('tests/data/valid_wifs.json') as f:
        return [read_addr_fixture_info(e) for e in json.load(f) if not e[2]['isPrivkey']]


class TestAddress:
    def test_create(self):
        Address('a' * 20, networks.livenet, Address.Type.PublicKey)
        Address('a' * 20, networks.livenet, Address.Type.Script)
        Address('a' * 20, networks.testnet, Address.Type.PublicKey)
        Address('a' * 20, networks.testnet, Address.Type.Script)

    def test_invalid_phash(self):
        with raises(Address.InvalidHashLength):
            Address('a')

    def test_invalid_network(self):
        with raises(Address.UnknownNetwork):
            Address('a' * 20, -1)

    def test_invalid_version(self):
        with raises(Address.InvalidVersion):
            Address.from_bytes(b'\x0f' + b'a' * 20)

    def test_invalid_type(self):
        with raises(Address.InvalidType):
            Address('a' * 20, networks.livenet, None)

    def test_from_hex(self):
        address = Address.from_hex(data['hex'])

        assert address.network is data['network']
        assert address.phash == decode_hex(data['phash'])
        assert address.type == data['type']
        assert address.to_string() == data['base58h']

    def test_from_invalid_hex(self):
        with raises(Address.InvalidHex): Address.from_hex('a')
        with raises(Address.InvalidHex): Address.from_hex('a@')

    def test_from_string(self):
        address = Address.from_string(data['base58h'])

        assert address.network is data['network']
        assert address.phash == decode_hex(data['phash'])
        assert address.type == data['type']
        assert address.to_hex() == data['hex']

    def test_from_invalid_string(self):
        with raises(Address.InvalidBase58h): Address.from_string('a')
        with raises(Address.InvalidBase58h): Address.from_string('a@')

    def test_from_invalid_bytes(self):
        with raises(Address.InvalidBinaryLength):
            Address.from_bytes('a')


    def test_from_pubkey(self):
        pubkey  = PublicKey(data['pubkey'], data['network'])
        address = Address.from_public_key(pubkey)

        assert address == Address.from_string(data['base58h'])


    def test_bitcoind_addresses(self, valid_addresses):
        for string_b58h, string_hex, network, type in valid_addresses:
            address = Address.from_string(string_b58h)

            assert address.network is network
            assert address.type == type
            assert address.to_string() == string_b58h
            assert encode_hex(address.phash) == string_hex.encode('utf-8')
