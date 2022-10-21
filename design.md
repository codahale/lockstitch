# The Design Of Lockstitch

## Preliminaries

### Initializing A Protocol

The basic unit of Lockstitch is the protocol, which is essentially a BLAKE3 hash. Every protocol is
initialized with a domain separation string, which is used to initialize a BLAKE3 hash in key
derivation function (KDF) mode:

```text
function Initialize(domain):
  state ← BLAKE3::KDF(domain)
  return state
```

### Encoding An Operation

Given this state, Lockstitch defines an unambiguous encoding for operations (similar to TupleHash).
Each operation begins by updating the protocol's state with the operation's unique 1-byte code:

```text
state ← BLAKE3::Update(state, [operation])
```

Having begun, an operation may update the protocol's state with operation-specific data.

Once an operation is complete, the protocol's state is updated with the operation's 1-byte code with
the MSB set and the number of bytes processed in the operation encoded as a 64-bit little-endian
integer:

```text
state ← BLAKE3::Update(state, [operation | 0b1000_0000])
state ← BLAKE3::Update(state, LE64(count))
```

This allows for the unambiguous encoding of multiple inputs and different types of operations as
well as operations which produce outputs which do not directly update the protocol's state.

### Generating Output

To generate any output during an operation, the protocol produces two 32-byte keys from the first 64
bytes of XOF output from its BLAKE3 hash. The protocol then replaces its current state with a
BLAKE3 keyed hash created with the first key. Finally, a ChaCha8 stream is initialized with the
second key (with a counter of zero) and used to produce output.

```text
K_0||K_1 ← BLAKE3::XOF(state, 64)
state ← BLAKE3::Keyed(K_0)
chacha ← ChaCha8::New(K_1)
```

While BLAKE3 can produce outputs of arbitrary length, Lockstitch uses ChaCha8 exclusively to
generate output values. This is done primarily to provide a clean separation of responsibilities in
the design. BLAKE3 effectively functions as a chained KDF, a task for which it was designed and for
which its fitness can be clearly analyzed. ChaCha8 functions as a pseudo-random function (PRF), a
task for which is was designed as well. Finally, despite the strong structural similarities between
ChaCha and BLAKE3's XOF, the use of ChaCha8 provides a performance benefit due to the reduced number
of rounds in the compression function.

## Primitive Operations

Lockstitch supports four primitive operations: `Mix`, `Derive`, `Encrypt`/`Decrypt`, and
`Tag`/`CheckTag`.

### `Mix`

`Mix` takes a byte sequence of arbitrary length and makes the protocol's state dependent on it:

```text
function Mix(state, data):
  state ← BLAKE3::Update(state, [0x01])       // Begin the operation.
  state ← BLAKE3::Update(state, data)         // Update the protocol's state with the data.
  state ← BLAKE3::Update(state, [0x41])       // End the operation with the code and length.
  state ← BLAKE3::Update(state, LE64(|data|))
  return state
```

Unlike a standard hash function, `Mix` operations (as with all other operations) are not
commutative. That is, `Mix("alpha"); Mix("bet")` is not equivalent to `Mix("alphabet")`.

### `Derive`

`Derive` produces a pseudo-random byte sequence of arbitrary length:

```text
function Derive(state, n):
  state ← BLAKE3::Update(state, [0x02])    // Begin the operation.
  (K_0, K_1) ← BLAKE3::Finalize(state, 64) // Finalize the state into two keys.
  state ← BLAKE3::Keyed(K_0)               // Replace the protocol's state with a new keyed hash.
  prf ← ChaCha8::Output(K_1, n)            // Produce n bytes of ChaCha8 output.
  state ← BLAKE3::Update(state, [0x42])    // End the operation with the code and the length.
  state ← BLAKE3::Update(state, LE64(n))
  return (state, prf) 
```

### `Encrypt`/`Decrypt`

`Encrypt` uses ChaCha8 to encrypt a given plaintext with a key derived from the protocol's current
state and updates the protocol's state with the plaintext itself.

```text
function Encrypt(state, plaintext):
  state ← BLAKE3::Update(state, [0x03])            // Begin the operation.
  (K_0, K_1) ← BLAKE3::Finalize(state, 64)         // Finalize the state into two keys.
  state ← BLAKE3::Keyed(K_0)                       // Replace the protocol's state with a new keyed hash.
  state ← BLAKE3::Update(state, plaintext)         // Update the protocol's state with the plaintext.
  prf ← ChaCha8::Output(K_1, |plaintext|)          // Produce a ChaCha8 keystream.
  ciphertext ← plaintext ^ prf                     // Encrypt the plaintext with ChaCha8 via XOR.
  state ← BLAKE3::Update(state, [0x43])            // End the operation with the code and the length.
  state ← BLAKE3::Update(state, LE64(|plaintext|))
  return (state, ciphertext) 
```

`Decrypt` is used to decrypt the outputs of `Encrypt`.

```text
function Decrypt(state, ciphertext):
  state ← BLAKE3::Update(state, [0x03])             // Begin the operation.
  (K_0, K_1) ← BLAKE3::Finalize(state, 64)          // Finalize the state into two keys.
  state ← BLAKE3::Keyed(K_0)                        // Replace the protocol's state with a new keyed hash.
  prf ← ChaCha8::Output(K_1, |ciphertext|)          // Produce a ChaCha8 keystream.
  plaintext ← ciphertext ^ prf                      // Decrypt the ciphertext with ChaCha8 via XOR.
  state ← BLAKE3::Update(state, plaintext)          // Update the protocol's state with the plaintext.
  state ← BLAKE3::Update(state, [0x43])             // End the operation with the code and the length.
  state ← BLAKE3::Update(state, LE64(|ciphertext|))
  return (state, plaintext) 
```

Three points bear mentioning about `Encrypt` and `DECRYPT`.

First, they provide no authentication by themselves. An attacker can modify a ciphertext and the
`Decrypt` operation will return a plaintext which was never encrypted. (That is, they are IND-CPA
secure but not IND-CCA secure.)

Second, both `Encrypt` and `Decrypt` use the same `Crypt` operation code to ensure protocols have
the same state after both encrypting and decrypting data. The only difference between the two
operations is the order of operations. `Encrypt` updates the state before XORing with the keystream;
`Decrypt` updates the state afterwards.

Finally, `Crypt` operations update the protocol's state with the plaintext, not with the ciphertext.
See the discussion on [Authenticated Encryption And Data
(AEAD)](#authenticated-encryption-and-data-aead) and [Signcryption](#signcryption) for why this is
important.

### `Tag`/`CheckTag`

The `Tag` operation produces a 16-byte authentication tag from ChaCha8 output:

```text
function Tag(state):
  state ← BLAKE3::Update(state, [0x04])    // Begin the operation.
  (K_0, K_1) ← BLAKE3::Finalize(state, 64) // Finalize the state into two keys.
  state ← BLAKE3::Keyed(K_0)               // Replace the protocol's state with a new keyed hash.
  tag ← ChaCha8::Output(K_1, 16)           // Produce 16 bytes of ChaCha8 output.
  state ← BLAKE3::Update(state, [0x44])    // End the operation with the code and the length.
  state ← BLAKE3::Update(state, LE64(16))
  return (state, tag) 
```

The `CheckTag` operation compares a received tag with a counterfactual tag produced by the `Tag`
operation:

```text
function CheckTag(state, tag):
  (state, tag') ← Tag(state)
  return (state, tag == tag')
```

Authentication tags are compared using a constant time algorithm to prevent timing attacks.

## Compound Operations

By combining operations, we can use Lockstitch to construct a wide variety of cryptographic schemes.

### Message Digests

```text
function MessageDigest(data):
  state ← Initialize("com.example.md")
  state ← Mix(state, data)
  (state, digest) ← Derive(state, 32)
  return digest
```

### Message Authentication Codes

```text
function Mac(key, data):
  state ← Initialize("com.example.mac")
  state ← Mix(state, key)
  state ← Mix(state, data)
  (state, tag) ← Tag(state)
  return tag
```

### Authenticated Encryption And Data (AEAD)

```text
function Seal(key, nonce, ad, plaintext):
  state ← Initialize("com.example.aead")
  state ← Mix(state, key)
  state ← Mix(state, nonce)
  state ← Mix(state, ad)
  (state, ciphertext) ← Encrypt(state, plaintext)
  (state, tag) ← Tag(state)
  return (ciphertext, tag)
```

```text
function Open(key, nonce, ad, ciphertext, tag):
  state ← Initialize("com.example.aead")
  state ← Mix(state, key)
  state ← Mix(state, nonce)
  state ← Mix(state, ad)
  (state, plaintext) ← Decrypt(state, ciphertext)
  (state, tag_ok) ← CheckTag(state, tag)
  if tag_ok:
    return ⊥
  else:
    return plaintext
```

This is effectively an Encrypt-And-Authenticate construction (as opposed to
Authenticate-Then-Encrypt or Encrypt-Then-Authenticate), which is IND-CCA secure with two caveats.

First, if the authentication tag reveals anything about the plaintext, the result will be UF-CMA
secure (i.e. an attacker cannot forge new valid ciphertexts) but not EAV secure (e.g. a MAC
algorithm which includes part of the message in the tag would allow a passive eavesdropper to read
plaintext). Lockstitch's `Tag` operation leaks no information about its inputs if BLAKE3 is
collision resistant.

Second, if the authentication tag is deterministic, the result will not be IND-CPA secure because
attacker can identity when the same message is sent twice by examining the tags. Because the ChaCha8
key of the `Tag` operation is derived from the same BLAKE3 hash chain which produced the key for the
`Encrypt` operation, the authentication tag will only be deterministic if the encryption keystream
is deterministic. The use of a nonce in this construction ensures both encryption and authentication
are probabilistic.

While Encrypt-Then-Authentication is the less contentious choice, Encrypt-And-Authenticate has
significant benefits with more complex constructions like [signcryption](#signcryption).

## Complex Protocols

Given an elliptic curve group like Ristretto255, Lockstitch can be used to build complex protocols
with asymmetric encryption.

### Hybrid Public-Key Encryption

```text
function HPKE_Encrypt(receiver.pub, plaintext):
  ephemeral ← Ristretto255::KeyGen()
  state ← Initialize("com.example.hpke")
  state ← Mix(state, receiver.pub)
  state ← Mix(state, ephemeral.pub)
  state ← Mix(state, ECDH(receiver.pub, ephemeral.priv))
  (state, ciphertext) ← Encrypt(state, plaintext)
  (state, tag) ← Tag(state)
  return (ephemeral.pub, ciphertext, tag)
```

```text
function HPKE_Decrypt(receiver, ephemeral.pub, ciphertext, tag):
  state ← Initialize("com.example.hpke")
  state ← Mix(state, receiver.pub)
  state ← Mix(state, ephemeral.pub)
  state ← Mix(state, ECDH(ephemeral.pub, receiver.priv))
  (state, plaintext) ← Decrypt(state, ciphertext)
  (state, tag) ← Tag(state)
  (state, tag_ok) ← CheckTag(state, tag)
  if tag_ok:
    return ⊥
  else:
    return plaintext
```

### Fiat-Shamir Transforms

```text
function Sign(signer, message):
  state ← Initialize("com.example.eddsa")
  state ← Mix(state, signer.pub)
  state ← Mix(state, message)
  (k, I) ← Ristretto255::KeyGen()
  state ← Mix(state, I)
  (state, r) ← Ristretto255::Scalar(Derive(state, 64))
  s ← signer.priv * r + k
  return (I, s)
```

```text
function Verify(signer.pub, message, I, s):
  state ← Initialize("com.example.eddsa")
  state ← Mix(state, signer.pub)
  state ← Mix(state, message)
  state ← Mix(state, I)
  (state, r') ← Ristretto255::Scalar(Derive(state, 64))
  I' ← [s]G - [r']signer.pub
  return I = I'
```

### Signcryption

```text
function Signcrypt(sender, receiver.pub, plaintext):
  ephemeral ← Ristretto255::KeyGen()
  state ← Initialize("com.example.signcrypt")
  state ← Mix(state, receiver.pub)
  state ← Mix(state, sender.pub)
  state ← Mix(state, ephemeral.pub)
  state ← Mix(state, ECDH(receiver.pub, ephemeral.priv))
  (state, ciphertext) ← Encrypt(state, plaintext)
  (k, I) ← Ristretto255::KeyGen()
  state ← Mix(state, I)
  (state, r) ← Ristretto255::Scalar(Derive(state, 64))
  s ← sender.priv * r + k
  return (ephemeral.pub, ciphertext, I, s)
```

```text
function Unsigncrypt(receiver, sender.pub, ephemeral.pub, I, s):
  state ← Initialize("com.example.signcrypt")
  state ← Mix(state, receiver.pub)
  state ← Mix(state, sender.pub)
  state ← Mix(state, ephemeral.pub)
  state ← Mix(state, ECDH(ephemeral.pub, receiver.priv))
  (state, plaintext) ← Decrypt(state, ciphertext)
  state ← Mix(state, I)
  (state, r') ← Ristretto255::Scalar(Derive(state, 64))
  I' ← [s]G - [r']sender.pub
  if I ≠ I':
    return ⊥
  return plaintext
```
