import sys

PY2 = sys.version_info[0] == 2
PY3 = sys.version_info[0] == 3


def chr(n):
    return bytes(bytearray([n]))


if PY2:
    string_types = basestring
else:
    string_types = str
