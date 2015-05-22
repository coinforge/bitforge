from urllib import urlencode
from urlparse import urlparse, parse_qsl

from bitforge import Address, Unit


class URI(object):

    @staticmethod
    def is_valid(uri):
        try:
            URI(uri)
            return True
        except:
            return False

    @staticmethod
    def parse(uri):
        parsed = urlparse(uri)
        data = dict(parse_qsl(parsed.query))
        data['address'] = parsed.path or parsed.netloc
        return data

    def __init__(self, args):
        if isinstance(args, str):
            args = URI.parse(args)
            if 'amount' in args:
                args['amount'] = Unit(btc = float(args['amount'])).satoshis
        elif not isinstance(args, dict):
            raise ValueError('Invalid arguments')

        self._build_from_dict(args)

    def _build_from_dict(self, args):
        MEMBERS = ['address', 'amount', 'message', 'label', 'r']
        self.extras = {}

        for k, v in args.iteritems():
            if k in MEMBERS:
                setattr(self, k, v)
            else:
                self.extras[k] = v

        self.address = Address.from_string(self.address)
        self.amount = Unit(satoshis = self.amount) if 'amount' in args else None

    def to_uri(self):
        query = self.extras.copy()
        if self.amount:
            query['amount'] = self.amount.btc
        for key in ['message', 'label', 'r']:
            value = getattr(self, key, False)
            if value:
                query[key] = value

        query = urlencode(query)
        return 'bitcoin:' + self.address.to_string() + ('?' + query if query else '')

    def __repr__(self):
        return '<URI: %s>' % self.to_uri()
