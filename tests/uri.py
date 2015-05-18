from bitforge import URI
from bitforge import Address
from bitforge import Unit
from bitforge import network


class TestURI:

    def test_parse_uri(self):
        uri = URI.parse('bitcoin:1DP69gMMvSuYhbnxsi4EJEFufUAbDrEQfj')
        assert uri['address'] == u'1DP69gMMvSuYhbnxsi4EJEFufUAbDrEQfj'

    def test_parse_uri_amount(self):
        uri = URI.parse('bitcoin:1DP69gMMvSuYhbnxsi4EJEFufUAbDrEQfj?amount=123.22')
        assert uri['address'] == u'1DP69gMMvSuYhbnxsi4EJEFufUAbDrEQfj'
        assert uri['amount'] == u'123.22'

    def test_uri_extras(self):
        uri = URI.parse('bitcoin:1DP69gMMvSuYhbnxsi4EJEFufUAbDrEQfj?amount=123.22&other-param=something&req-extra=param')
        assert uri['address'] == '1DP69gMMvSuYhbnxsi4EJEFufUAbDrEQfj'
        assert uri['amount'] == '123.22'
        assert uri['other-param'] == u'something'
        assert uri['req-extra'] == u'param'

    def test_is_valid(self):
        assert URI.is_valid('bitcoin:1DP69gMMvSuYhbnxsi4EJEFufUAbDrEQfj')
        assert URI.is_valid('bitcoin:mkYY5NRvikVBY1EPtaq9fAFgquesdjqECw')

        assert URI.is_valid('bitcoin:1DP69gMMvSuYhbnxsi4EJEFufUAbDrEQfj?amount=1.2')
        assert URI.is_valid('bitcoin:1DP69gMMvSuYhbnxsi4EJEFufUAbDrEQfj?amount=1.2&other=param')
        assert URI.is_valid('bitcoin:mmrqEBJxUCf42vdb3oozZtyz5mKr3Vb2Em?amount=0.1&r=https%3A%2F%2Ftest.bitpay.com%2Fi%2F6DKgf8cnJC388irbXk5hHu')

        assert not URI.is_valid('bitcoin:')
        assert not URI.is_valid('bitcoin:badUri')
        assert not URI.is_valid('bitcoin:1DP69gMMvSuYhbnxsi4EJEFufUAbDrEQfk?amount=bad')
        assert not URI.is_valid('bitcoin:?r=https%3A%2F%2Ftest.bitpay.com%2Fi%2F6DKgf8cnJC388irbXk5hHu')

    def test_uri_address(self):
        uri = URI('bitcoin:1DP69gMMvSuYhbnxsi4EJEFufUAbDrEQfj')
        assert isinstance(uri.address, Address)
        assert uri.address.network == network.livenet

        uri = URI('bitcoin:mkYY5NRvikVBY1EPtaq9fAFgquesdjqECw')
        assert isinstance(uri.address, Address)
        assert uri.address.network == network.testnet

    def test_uri_amount(self):
        uri = URI('bitcoin:1DP69gMMvSuYhbnxsi4EJEFufUAbDrEQfj?amount=123.22')
        assert isinstance(uri.amount, Unit)
        assert uri.amount.satoshis == 12322000000

    def test_uri_extras_2(self):
        uri = URI('bitcoin:1DP69gMMvSuYhbnxsi4EJEFufUAbDrEQfj?amount=1.2&other=param')
        assert uri.extras['other'] == u'param'

    def test_create_params(self):
        uri = URI({
            'address': '1DP69gMMvSuYhbnxsi4EJEFufUAbDrEQfj',
            'amount' : 120000000,
            'other'  : 'param'
        })

        assert isinstance(uri.address, Address)
        assert isinstance(uri.amount, Unit) and uri.amount.satoshis == 120000000
        assert uri.extras['other'] == u'param'

    def test_create_required(self):
        uri = URI({
            'address'  : '1DP69gMMvSuYhbnxsi4EJEFufUAbDrEQfj',
            'req-other': 'param'
        })

        assert isinstance(uri.address, Address)
        assert uri.extras['req-other'] == u'param'

    def test_parse_support(self):
        uri = URI('bitcoin://1DP69gMMvSuYhbnxsi4EJEFufUAbDrEQfj')
        assert uri.address.to_string() == '1DP69gMMvSuYhbnxsi4EJEFufUAbDrEQfj'

    def test_str_roundtrip(self):
        uri = 'bitcoin:1DP69gMMvSuYhbnxsi4EJEFufUAbDrEQfj?message=Donation+for+project+xyz&other=xD&label=myLabel'
        assert URI(uri).to_uri() == uri

    def test_support_url_ecoded(self):
        uri = URI('bitcoin:1DP69gMMvSuYhbnxsi4EJEFufUAbDrEQfj?message=Donation+for+project+xyz&other=xD&label=myLabel')
        assert uri.message == u'Donation for project xyz'
        assert uri.label == u'myLabel'
        assert uri.extras['other'] == u'xD'

    def test_str(self):
        uri = URI({'address': '1DP69gMMvSuYhbnxsi4EJEFufUAbDrEQfj'})
        assert uri.to_uri() == 'bitcoin:1DP69gMMvSuYhbnxsi4EJEFufUAbDrEQfj'

        uri = URI({
            'address': '1DP69gMMvSuYhbnxsi4EJEFufUAbDrEQfj',
            'amount': 110001000,
            'message': 'Hello World',
            'something': 'else'
        })

        assert uri.to_uri() == 'bitcoin:1DP69gMMvSuYhbnxsi4EJEFufUAbDrEQfj?amount=1.10001&message=Hello+World&something=else'

    def test_protocol_case_insensitive(self):
        uri1 = URI('bItcOin:1DP69gMMvSuYhbnxsi4EJEFufUAbDrEQfj')
        uri2 = URI('bitcoin:1DP69gMMvSuYhbnxsi4EJEFufUAbDrEQfj')
        assert uri1.to_uri() == uri2.to_uri()

    def test_encondes_r_correctly(self):
        uri = 'bitcoin:mmrqEBJxUCf42vdb3oozZtyz5mKr3Vb2Em?amount=0.1&r=https%3A%2F%2Ftest.bitpay.com%2Fi%2F6DKgf8cnJC388irbXk5hHu'
        assert URI(uri).to_uri() == uri

    def test_repr(self):
        uri = URI('bitcoin:1DP69gMMvSuYhbnxsi4EJEFufUAbDrEQfj')
        assert repr(uri) == '<URI: bitcoin:1DP69gMMvSuYhbnxsi4EJEFufUAbDrEQfj>'
