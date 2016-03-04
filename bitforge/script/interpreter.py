from bitforge import Transaction
from bitforge.tools import Buffer


class Interpreter(object):

    def __init__(self):
        self.initialize()

    def initialize(self):
        self.stack = []
        self.altstack = []
        self.pc = 0
        self.pbegincodehash = 0
        self.nop_count = 0
        self.vf_exec = []
        self.errstr = ''
        self.flags = 0


    """
    Verifies a Script by executing it and returns true if it is valid.
    This function needs to be provided with the scriptSig and the scriptPubkey
    separately.

    :param script_sig: the script's first part (corresponding to the tx input)
    :param script_pubkey: the script's last part (corresponding to the tx output)
    :param tx: the transaction containing the script_sig in one input (used to
        check signature validity for some opcodes like OP_CHECKSIG)
    :param nin: index of the transaction input containing the scriptSig verified.
    :param flags: evaluation flags. See Interpreter.SCRIPT_* constants

    Translated from bitcoind's VerifyScript
    """
    def verify(self, script_sig, script_pubkey, tx, nin, flags):
        self.script = script_sig
        self.tx = tx or Transaction([], [])
        self.nin = nin or 0
        self.flags = flags or 0

        return False

    # Interpreter constants
    true = Buffer([1])
    false = Buffer([])

    MAX_SCRIPT_ELEMENT_SIZE = 520
    LOCKTIME_THRESHOLD = 500000000

    # Flags taken from bitcoind
    # bitcoind commit: b5d1b1092998bc95313856d535c632ea5a8f9104
    SCRIPT_VERIFY_NONE = 0

    # Evaluate P2SH subscripts (softfork safe, BIP16).
    SCRIPT_VERIFY_P2SH = 1 << 0

    # Passing a non-strict-DER signature or one with undefined hashtype to a checksig operation causes script failure.
    # Passing a pubkey that is not (0x04 + 64 bytes) or (0x02 or 0x03 + 32 bytes) to checksig causes that pubkey to be
    # skipped (not softfork safe: this flag can widen the validity of OP_CHECKSIG OP_NOT).
    SCRIPT_VERIFY_STRICTENC = 1 << 1

    # Passing a non-strict-DER signature to a checksig operation causes script failure (softfork safe, BIP62 rule 1)
    SCRIPT_VERIFY_DERSIG = 1 << 2

    # Passing a non-strict-DER signature or one with S > order/2 to a checksig operation causes script failure
    # (softfork safe, BIP62 rule 5).
    SCRIPT_VERIFY_LOW_S = 1 << 3

    # Verify dummy stack item consumed by CHECKMULTISIG is of zero-length (softfork safe, BIP62 rule 7).
    SCRIPT_VERIFY_NULLDUMMY = 1 << 4

    # Using a non-push operator in the scriptSig causes script failure (softfork safe, BIP62 rule 2).
    SCRIPT_VERIFY_SIGPUSHONLY = 1 << 5

    # Require minimal encodings for all push operations (OP_0... OP_16, OP_1NEGATE where possible, direct
    # pushes up to 75 bytes, OP_PUSHDATA up to 255 bytes, OP_PUSHDATA2 for anything larger). Evaluating
    # any other push causes the script to fail (BIP62 rule 3).
    # In addition, whenever a stack element is interpreted as a number, it must be of minimal length (BIP62 rule 4).
    # (softfork safe)
    SCRIPT_VERIFY_MINIMALDATA = 1 << 6

    # Discourage use of NOPs reserved for upgrades (NOP1-10)
    #
    # Provided so that nodes can avoid accepting or mining transactions
    # containing executed NOP's whose meaning may change after a soft-fork,
    # thus rendering the script invalid; with this flag set executing
    # discouraged NOPs fails the script. This verification flag will never be
    # a mandatory flag applied to scripts in a block. NOPs that are not
    # executed, e.g.  within an unexecuted IF ENDIF block, are *not* rejected.
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS = 1 << 7

    # CLTV See BIP65 for details.
    SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY = 1 << 9
