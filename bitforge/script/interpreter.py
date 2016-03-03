
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
        pass
