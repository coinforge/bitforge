from __future__ import unicode_literals

SIGHASH_ALL = 0x01


def validate_signature(sig):
    # Minimum and maximum size constraints.
    sig = map(ord, sig)

    if (len(sig) < 9): return False;
    if (len(sig) > 73): return False;

    # A signature is of type 0x30 (compound).
    if (sig[0] != 0x30): return False;

    # Make sure the length covers the entire signature.
    if (sig[1] != len(sig) - 3): return False;

    # Extract the length of the R element.
    lenR = sig[3]

    # Make sure the length of the S element is still inside the signature.
    if (5 + lenR >= len(sig)): return False;

    # Extract the length of the S element.
    lenS = sig[5 + lenR];

    # Verify that the length of the signature matches the sum of the length
    # of the elements.
    if ((lenR + lenS + 7) != len(sig)): return False;

    # Check whether the R element is an integer.
    if (sig[2] != 0x02): return False;

    # Zero-length integers are not allowed for R.
    if (lenR == 0): return False;

    # Negative numbers are not allowed for R.
    if (sig[4] & 0x80): return False;

    # Null bytes at the start of R are not allowed, unless R would
    # otherwise be interpreted as a negative number.
    if (lenR > 1 and (sig[4] == 0x00) and not (sig[5] & 0x80)):
        return False;

    # Check whether the S element is an integer.
    if (sig[lenR + 4] != 0x02): return False;

    # Zero-length integers are not allowed for S.
    if (lenS == 0): return False;

    # Negative numbers are not allowed for S.
    if (sig[lenR + 6] & 0x80): return False;

    # Null bytes at the start of S are not allowed, unless S would otherwise be
    # interpreted as a negative number.
    if (lenS > 1 and (sig[lenR + 6] == 0x00) and not (sig[lenR + 7] & 0x80)): return False;

    return True;
