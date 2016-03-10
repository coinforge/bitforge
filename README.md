# Bitforge

[![Build Status](https://travis-ci.org/coinforge/bitforge.svg?branch=master&style=flat-square)](https://travis-ci.org/coinforge/bitforge)

The next great Bitcoin library, written in pure Python, **currently in beta and under
development**.

`Bitforge` provides a solid model of Bitcoin objects, through method-rich immutable
instances and precise error descriptions.

Currently, `Bitforge` supports:

- Key creation and handling, with `PrivateKey` and `PublicKey`
- Key derivation, with `HDPrivateKey` and `HDPublicKey`
- Script compilation and evaluation, through `Script` and `Interpreter`
- Pay-to-Pubkey and Pay-to-Script, with `Input`, `Output`, and their subclasses
- Transaction creation and signing, through `Transaction`

This is enough to create, sign and serialize a multisig `Transaction`. The
process takes 5-10 lines of code.

`Bitforge` will eventually provide:

- A high-level _fluent_ interface, with progressive builders to wrap the immutable
layer below.
- Full test coverage (currently partial)


# Examples

##### Send bitcoins from an address to another

```python
from bitforge import PrivateKey, AddressInput, AddressOutput, Transaction

# 1. Create an AddressInput with details from the Unspent Transaction Output
in0 = AddressInput(
    tx_id     = '4baa7551933fbf26158a619c3084ccdd5c0d81930b3e74a85a33ad26d13f1a55',
    txo_index = 0,
    address   = Address.from_string('1Dy6qCRsjJ4Y3BYv7m9nf12aUMXD4RWMHC')
)

# 2. Create an AddressOutput that you can redeem with your PrivateKey:
privkey = PrivateKey.from_hex('21c601c0ae6dfcdcf622e6fe2be9153ed7ada0cc90a8a08475e57060e18c0791')

out0 = AddressOutput(
    amount  = 1000, # satoshis
    address = privkey.to_address()
)

# 3. Create the Transaction:
tx = Transaction(inputs = [ in0 ], outputs = [ out0 ])

# 4. Sign the first Input:
signed_tx = tx.signed([ privkey ], 0)
```


##### Send funds to a multisig address

```python
from bitforge import PrivateKey, AddressInput, MultisigOutput, Transaction

# 1. Create an AddressInput with details from the Unspent Transaction Output
in0 = AddressInput(
    tx_id     = '4baa7551933fbf26158a619c3084ccdd5c0d81930b3e74a85a33ad26d13f1a55',
    txo_index = 0,
    address   = Address.from_string('1Dy6qCRsjJ4Y3BYv7m9nf12aUMXD4RWMHC')
)


# 2. Create a MultisigOutput, given a known public keys and required signatures:
out0 = MultisigOutput(
    amount         = 1000,
    pubkeys        = [ pubkey1, pubkey2, pubkey3 ],
    min_signatures = 2
)

# 3. Create the Transaction:
tx = Transaction(inputs = [ in0 ], outputs = [ out0 ])

# 4. Sign the first Input:
signed_tx = tx.signed([ privkey ], 0)
```


# Object Model

All of the classes described below extend `namedtuple`. Once created, their
basic properties are **immutable**. They can be hashed, compared, printed and
serialized.

These basic classes are available for `import` in the `bitforge` module.

```python
from bitforge import PrivateKey, Transaction
```

## PrivateKey

##### `PrivateKey(secret = None, network = networks.default, compressed = True)`

A `PrivateKey` object holds a `secret` number, or generates a random `secret`
if `None` is provided. The `secret` must be an `int` between 1 and SECP256k1
maximum.

It's usually created using one of the factory methods listed below.


#### Static methods

##### `PrivateKey.from_bytes(bytes, network = networks.default, compressed = True)`
Create a new `PrivateKey` from a 32-byte binary `str` holding the `secret`.

##### `PrivateKey.from_hex(string, network = networks.default, compressed = True)`
Create a new `PrivateKey` from a 64-byte hexadecimal `str` holding the `secret`.

##### `PrivateKey.from_wif(string)`
Create a new `PrivateKey` from a WIF-encoded `str`. It already includes `network`
and `compressed`.


#### Instance methods

##### `.to_bytes()`
Returns the `secret` as a 32-byte `str`.

##### `.to_hex()`
Returns the `secret` as a 64-byte hexadecimal `str`.

##### `.to_wif()`
Returns a WIF-encoded key, including details from `network` and `compressed`.

##### `.to_public_key()`
Returns a matching `PublicKey` instance.

##### `.to_address()`
Same as `to_public_key().to_address()`.

##### `.sign(payload)`
Returns a binary `str` containing the signed `payload` in Bitcoin-compatible DER
format, using the SECPK256k1 elliptic curve.

##### `.verify(signature, payload)`
Verify that `signature` is valid for `payload`.



## PublicKey

##### `PublicKey(pair, network = networks.default, compressed = True)`

A `PublicKey` object holds a `pair` of coordinates in the Bitcoin elliptic
curve.

It's usually extracted from a `PrivateKey`, or created using one of the factory
methods listed below.


#### Static methods

##### `PublicKey.from_bytes(bytes, network = networks.default)`
Create a new `PublicKey` from a binary `str` holding a `pair`, auto-detecting
if it's `compressed`.

##### `PublicKey.from_hex(string, network = networks.default)`
Create a new `PublicKey` from a hexadecimal `pair`, auto-detecting if it's
`compressed`.


#### Instance methods

##### `.to_bytes()`
Return a binary `str` representing the `pair`, which may be `compressed`.

##### `.to_hex()`
Return a hexadecimal `str` representing the `pair`, which may be `compressed`

##### `.to_address()`
Return a matching `Address` instance.



## Address

##### `Address(phash, network = networks.default, type = Address.Type.PublicKey)`

An `Address` holds a Bitcoin address, hashed from a `PublicKey`.

It's usually extracted from a `PublicKey`, or created using one of the factory
methods listed below.


#### Static methods

##### `Address.from_string(string)`
Create a new `Address` from a base58check-encoded `str`, auto-detecting `network`
and `type`.

##### `Address.from_bytes(bytes)`
Create a new `Address` from a binary `str`, auto-detecting `network` and `type`.

##### `Address.from_hex(string, network = networks.default)`
Create a new `Address` from a hexadecimal `str`, auto-detecting `network` and
`type`.

##### `Address.from_public_key(pubkey)`
Create a new `Address`, derived from a `PublicKey`. Same as `pubkey.to_address()`.

##### `Address.from_script(script, network = networks.default)`
Create a new `Address` from a `Script`, for Pay-to-Script transactions.


#### Instance methods

##### `.to_string()`
Return a base58check-encoded `str` representing the `Address`, including the
network and type prefix.

##### `.to_bytes()`
Return a binary `str` representing the `Address`, including the network and type
prefix.

##### `.to_hex()`
Return a hexadecimal `str` representing the `Address`, including the network and
type prefix.



## Input

##### `Input(tx_id, txo_index, script, seq_number = FINAL_SEQ_NUMBER)`

A `Transaction` `Input`. `tx_id` and `txo_index` point to an unspent transaction
output.

The `Input` class can be instantiated directly, but the `signed()` method will
`raise`. To really work with `Inputs`, you should use or create a subclass.
These are available out-of-the-box, and described below:

```
Input
  ↳ AddressInput
  ↳ ScriptInput
      ↳ MultisigInput
```

All subclasses have their `Output` counterparts.


#### Static methods

##### `Input.from_bytes(bytes)`
Deserialize an `Input` from a binary `str`.

##### `Input.from_hex(string)`
Deserialize an `Input` from a hexadecimal `str`.

##### `Input.from_buffer(buffer)`
Read a serialized `Input` from a `Buffer` instance.


#### Instance methods

##### `.to_bytes()`
Serialize this `Input` to Bitcoin protocol format.

##### `.to_hex()`
Serialize this `Input` to Bitcoin protocol format, and return it as a hexadecimal
string.

##### `.with_script(script)`
Return a copy of this immutable `Input`, replacing the `script`.

##### `.without_script()`
Return a copy of this immutable `Input`, with an empty (0-byte) `script`.

##### `signed(privkeys, payload)`
Return a new `Input`, with the same `tx_id`, `txo_index` and `seq_number`. The
`script` will be replaced by a version including signatures.

To produce the signatures, the `payload` will be signed with all `privkeys`.

`Input` **does not implement this method**, as the inner workings change with
different transaction types. Subclasses provide it.


##### `AddressInput(tx_id, txo_index, address, seq_number = FINAL_SEQ_NUMBER)`

A _Pay-to-Pubkey-Hash_ `Input`, that can redeem funds sent to an `Address`. The
`signed()` method takes a list of `privkeys` with exactly `1` key.

This is the counterpart of `AddressOutput`.

```python
input = AddressInput(
  tx_id     = '4baa75...',
  txo_index = 0,
  address   = PrivateKey().to_public_key().to_address()
)
```


##### `ScriptInput(tx_id, txo_index, script, seq_number = FINAL_SEQ_NUMBER)`

A _Pay-to-Script-Hash_ `Input`. `script` must be an instance of `Script`.

This is the counterpart of `ScriptOutput`.

```python
input = ScriptInput(
  tx_id     = '4baa75...',
  txo_index = 0,
  script    = Script(...)
)
```


##### `MultisigInput(tx_id, txo_index, pubkeys, min_signatures, seq_number = FINAL_SEQ_NUMBER)`

A special case of _Pay-to-Script-Hash_ `Input`, where `script` is internally
set to a standard multi-signature `Script`.

Create it with an array of `PublicKey` `pubkeys`, and specify `min_signatures`.

This is the counterpart of `MultisigOutput`.

```python
input = MultisigInput(
  tx_id          = '4baa75...',
  txo_index      = 0,
  pubkeys        = [ PrivateKey().to_public_key(), PrivateKey().to_public_key() ],
  min_signatures = 1
)
```


## Output

##### `Output(amount, script)`

A `Transaction` `Output`. `amount` is an `int` of _satoshis_, `script` is a
`Script` instance.

The `Output` class can be instantiated directly, but the recommended approach is
to use or create a subclass. For each of the `Input` subclasses described above,
there is an `Output` subclass counterpart.

```
Output
  ↳ DataOutput
  ↳ AddressOutput
  ↳ ScriptOutput
      ↳ MultisigOutput
```

#### Static methods

##### `Output.from_bytes(bytes)`
Deserialize an `Output` from a binary `str`.

##### `Output.from_hex(string)`
Deserialize an `Output` from a hexadecimal `str`.

##### `Output.from_buffer(buffer)`
Read a serialized `Output` from a `Buffer` instance.


#### Instance methods

##### `.to_bytes()`
Serialize this `Output` to Bitcoin protocol format.

##### `.to_hex()`
Serialize this `Output` to Bitcoin protocol format, and return it as a hexadecimal
string.

##### `DataOutput(bytes)`

A non-redeemable `OP_RETURN` `Output` that includes up to `80` `bytes` of arbitrary
data in the transaction `Script`.

##### `AddressOutput(amount, address)`

A _Pay-to-Pubkey-Hash_ `Output`, that can send funds to an `Address`.

##### `ScriptOutput(amount, script)`

A _Pay-to-Script-Hash_ `Output`. `script` must be an instance of `Script`.

##### `MultisigOutput(amount, pubkeys, min_signatures)`

A special case of _Pay-to-Script-Hash_ `Output`, where `script` is internally
set to a standard multi-signature `Script`.

Create it with an array of `PublicKey` `pubkeys`, and specify `min_signatures`.


## Transaction

##### `Transaction(inputs, outputs, lock_time = 0, version = 1)`

A complete `Transaction`, created with a list of `Input` and `Output` instances,
and optionally with `lock_time` and `version`.

As all other basic objects, a `Transaction` is immutable. Modifications and
signatures produce new `Transaction` instances.


#### Static methods

##### `Transaction.from_bytes(bytes)`
Deserialize a `Transaction` from a binary `str`.

##### `Transaction.from_hex(string)`
Deserialize a `Transaction` from a hexadecimal `str`.


#### Instance methods

##### `.get_id()`
Return this `Transaction`'s Bitcoin ID.

##### `.to_bytes()`
Serialize this `Transaction` to Bitcoin protocol format.

##### `.to_hex()`
Serialize this `Transaction` to Bitcoin protocol format, and return it as a
hexadecimal string.

##### `signed(privkeys, txi_index)`

Return a copy of this `Transaction`, where the `Input` at `txi_index` has been
signed with all `privkeys`.

The method used to sign a particular `Input` is delegated to the input object
itself, as implemented by the corresponding `Input` subclass.


## Development

First, get the code:
```
git clone git@github.com:muun/bitforge.git; cd bitforge;
```

Then, create a new virtualenv for this project:
```
sudo pip install virtualenv
virtualenv env
```

Activate virtualenv:
```
source env/bin/activate
```

Then, install bitforge's dependencies:
```
pip install -r requirements.txt
```

Run the tests to make sure everything is working:
```
py.test tests/all.py
```
