# The Design Of Lockstitch

Lockstitch provides a single cryptographic primitive for all symmetric-key operations and an
incremental, stateful building block for complex schemes, constructions, and protocols.

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

Having begun, an operation may update the protocol's state with operation-specific data or replace
it entirely.

Once an operation is complete, the protocol's state is updated with the operation's 1-byte code with
the MSB set and the number of bytes processed in the operation encoded as a 64-bit little-endian
integer:

```text
state ← BLAKE3::Update(state, [operation | 0b1000_0000])
state ← BLAKE3::Update(state, LE64(count))
```

This allows for the unambiguous encoding of multiple inputs and different types of operations as
well as operations which produce outputs but do not directly update the protocol's state.

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
task for which is was designed as well.

Finally, despite the strong structural similarities between ChaCha and BLAKE3's XOF, the use of
ChaCha8 provides a performance benefit due to the reduced number of rounds in the compression
function.

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
commutative. That is, `Mix("alpha"); Mix("bet")` is not equivalent to `Mix("alphabet")`. This
eliminates the possibility of collisions; no additional padding or encoding is required.

`Mix` inherits the collision resistance of the underlying BLAKE3 algorithm.

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

`Derive` inherits the PRF security of ChaCha8 using the protocol's prior state as a key. Further,
the state of the protocol is overwritten with BLAKE3 output, making reversing it equivalent to
breaking BLAKE3's preimage resistance.

### `Encrypt`/`Decrypt`

`Encrypt` uses ChaCha8 to encrypt a given plaintext with a key derived from the protocol's current
state and updates the protocol's state with the plaintext itself.

```text
function Encrypt(state, plaintext):
  state ← BLAKE3::Update(state, [0x03])             // Begin the operation.
  (K_0, K_1) ← BLAKE3::Finalize(state, 64)          // Finalize the state into two keys.
  state ← BLAKE3::Keyed(K_0)                        // Replace the protocol's state with a new keyed hash.
  prf ← ChaCha8::Output(K_1, |plaintext|)           // Produce a ChaCha8 keystream.
  ciphertext ← plaintext ^ prf                      // Encrypt the plaintext with ChaCha8 via XOR.
  state ← BLAKE3::Update(state, ciphertext)         // Update the protocol's state with the ciphertext.
  state ← BLAKE3::Update(state, [0x43])             // End the operation with the code and the length.
  state ← BLAKE3::Update(state, LE64(|ciphertext|))
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
  state ← BLAKE3::Update(state, ciphertext)         // Update the protocol's state with the ciphertext.
  state ← BLAKE3::Update(state, [0x43])             // End the operation with the code and the length.
  state ← BLAKE3::Update(state, LE64(|ciphertext|))
  return (state, plaintext) 
```

Two points bear mentioning about `Encrypt` and `Decrypt`.

First, both `Encrypt` and `Decrypt` use the same `Crypt` operation code to ensure protocols have
the same state after both encrypting and decrypting data.

Second, they provide no authentication by themselves. An attacker can modify a ciphertext and the
`Decrypt` operation will return a plaintext which was never encrypted. Alone, they are EAV secure
(i.e. a passive adversary will not be able to read plaintext without knowing the protocol's prior
state) but not IND-CPA secure (i.e. an active adversary with an encryption oracle will be able to
detect duplicate plaintexts) or IND-CCA secure (i.e. an active adversary can produce modified
ciphertexts which successfully decrypt). For IND-CPA and IND-CCA security, `Encrypt`/`Decrypt`
operations must be part of an integrated protocol (e.g. an
[AEAD](#authenticated-encryption-and-data-aead)).

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

This is structurally the same as the `Derive` operation but with a dedicated operation code and a
fixed length. The specific operation code provides domain separation for output which is usually
passed in the clear (whereas `Derive` output is often used as inputs for additional processes).
Fixing the length at 128 bits provides users with the maximum security available given the size of
the state space.

The `CheckTag` operation compares a received tag with a counterfactual tag produced by the `Tag`
operation:

```text
function CheckTag(state, tag):
  (state, tag') ← Tag(state) // Calculate the counterfactual tag.
  return (state, tag ⊜ tag') // Compare the two in constant time.
```

## Compound Operations

By combining operations, we can use Lockstitch to construct a wide variety of cryptographic schemes
using a single protocol.

### Message Digests

Calculating a message digest is as simple as a `Mix` and a `Derive`:

```text
function MessageDigest(data):
  state ← Initialize("com.example.md") // Initialize a protocol with a domain string.
  state ← Mix(state, data)             // Mix the data into the protocol.
  (state, digest) ← Derive(state, 32)  // Derive 32 bytes of output and return it.
  return digest
```

This is essentially equivalent to using BLAKE3 with ChaCha8 as an XOF. As such, it inherits
BLAKE3's collision resistance.

### Message Authentication Codes

Adding a key to the previous construction and swapping the `Derive` for a `Tag` makes it a MAC:

```text
function Mac(key, data):
  state ← Initialize("com.example.mac") // Initialize a protocol with a domain string.
  state ← Mix(state, key)               // Mix the key into the protocol.
  state ← Mix(state, data)              // Mix the data into the protocol.
  (state, tag) ← Tag(state)             // Create and return a tag.
  return tag
```

The [operation encoding](#encoding-an-operation) ensures that the key and the data will never
overlap, even if their lengths vary.

The `CheckTag` operation provides a secure way to verify the MAC:

```text
function VerifyMac(key, data, tag):
  state ← Initialize("com.example.mac") // Initialize a protocol with a domain string.
  state ← Mix(state, key)               // Mix the key into the protocol.
  state ← Mix(state, data)              // Mix the data into the protocol.
  (state, ok) ← CheckTag(state, tag)    // Check the tag.
  return ok
```

### Authenticated Encryption And Data (AEAD)

Lockstitch can be used to create an AEAD:

```text
function Seal(key, nonce, ad, plaintext):
  state ← Initialize("com.example.aead")          // Initialize a protocol with a domain string.
  state ← Mix(state, key)                         // Mix the key into the protocol.
  state ← Mix(state, nonce)                       // Mix the nonce into the protocol.
  state ← Mix(state, ad)                          // Mix the associated data into the protocol.
  (state, ciphertext) ← Encrypt(state, plaintext) // Encrypt the plaintext.
  (state, tag) ← Tag(state)                       // Create a tag.
  return (ciphertext, tag)                        // Return the ciphertext and tag.
```

The introduction of a nonce makes the scheme probabilistic (which is required for IND-CCA security).
The final `Tag` operation closes over all inputs--key, nonce, associated data, and plaintext--which
are also the values used to produce the ciphertext. Forging a tag here would imply that BLAKE3's MAC
construction is not sUF-CMA secure, which would imply it is not collision resistant.

In addition, this construction is compactly committing: finding a ciphertext and tag pair which
successfully decrypts under multiple keys would imply either BLAKE3 is not collision-resistant or
ChaCha8 is not PRF-secure, and the final tag serves as a commitment for the ciphertext.

Decryption uses the `CheckTag` operation to verify the tag:

```text
function Open(key, nonce, ad, ciphertext, tag):
  state ← Initialize("com.example.aead")          // Initialize a protocol with a domain string.
  state ← Mix(state, key)                         // Mix the key into the protocol.
  state ← Mix(state, nonce)                       // Mix the nonce into the protocol.
  state ← Mix(state, ad)                          // Mix the associated data into the protocol.
  (state, plaintext) ← Decrypt(state, ciphertext) // Decrypt the ciphertext.
  (state, ok) ← CheckTag(state, tag)              // Check the tag to authenticate.
  if ok:
    return plaintext                              // If authentic, return the plaintext.
  else:
    return ⊥                                      // Otherwise, return an error.
```

## Complex Protocols

Given an elliptic curve group like Ristretto255, Lockstitch can be used to build complex protocols
which integrate public- and symmetric-key operations.

### Hybrid Public-Key Encryption

Lockstitch can be used to build an integrated
[ECIES](https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme)-style public key encryption
scheme:

```text
function HPKE_Encrypt(receiver.pub, plaintext):
  ephemeral ← Ristretto255::KeyGen()                     // Generate an ephemeral key pair.
  state ← Initialize("com.example.hpke")                 // Initialize a protocol with a domain string.
  state ← Mix(state, receiver.pub)                       // Mix the receiver's public key into the protocol.
  state ← Mix(state, ephemeral.pub)                      // Mix the ephemeral public key into the protocol.
  state ← Mix(state, ECDH(receiver.pub, ephemeral.priv)) // Mix the ephemeral ECDH shared secret into the protocol.
  (state, ciphertext) ← Encrypt(state, plaintext)        // Encrypt the plaintext.
  (state, tag) ← Tag(state)                              // Generate a tag.
  return (ephemeral.pub, ciphertext, tag)                // Return the ephemeral public key, ciphertext, and tag.
```

```text
function HPKE_Decrypt(receiver, ephemeral.pub, ciphertext, tag):
  state ← Initialize("com.example.hpke")                 // Initialize a protocol with a domain string.
  state ← Mix(state, receiver.pub)                       // Mix the receiver's public key into the protocol.
  state ← Mix(state, ephemeral.pub)                      // Mix the ephemeral public key into the protocol.
  state ← Mix(state, ECDH(ephemeral.pub, receiver.priv)) // Mix the ephemeral ECDH shared secret into the protocol.
  (state, plaintext) ← Decrypt(state, ciphertext)        // Decrypt the plaintext.
  (state, ok) ← CheckTag(state, tag)                     // Check the tag's validity.
  if ok:
    return plaintext                                     // Return the plaintext if the tag is valid.
  else:
    return ⊥                                             // Otherwise, return an error.
```

**N.B.:** This construction does not provide authentication in the public key setting. An adversary
in possession of the receiver's public key (i.e. anyone) can create ciphertexts which will decrypt
as valid. In the symmetric key setting (i.e. an adversary without the receiver's public key), this
is IND-CCA secure, but the real-world scenarios in which that applies are minimal. As-is, the tag
is more like a checksum than a MAC.

Using a static ECDH shared secret (i.e. `ECDH(receiver.pub, sender.priv)`) would add implicit
authentication but would require a nonce to be IND-CCA secure. The resulting scheme would be
outsider secure in the public key setting (i.e. an adversary in possession of everyone's public keys
would be unable to forge or decrypt ciphertexts) but not insider secure (i.e. an adversary in
possession of the receiver's private key could forge ciphertexts from arbitrary senders, a.k.a. key
compromise impersonation).

### Digital Signatures

Lockstitch can be used to implement EdDSA-style Schnorr digital signatures:

```text
function Sign(signer, message):
  state ← Initialize("com.example.eddsa")              // Initialize a protocol with a domain string.
  state ← Mix(state, signer.pub)                       // Mix the signer's public key into the protocol.
  state ← Mix(state, message)                          // Mix the message into the protocol.
  (k, I) ← Ristretto255::KeyGen()                      // Generate a commitment scalar and point.
  state ← Mix(state, I)                                // Mix the commitment point into the protocol.
  (state, r) ← Ristretto255::Scalar(Derive(state, 64)) // Derive a challenge scalar.
  s ← signer.priv * r + k                              // Calculate the proof scalar.
  return (I, s)                                        // Return the commitment point and proof scalar.
```

The resulting signature is strongly bound to both the message and the signer's public key, making it
sUF-CMA secure. If a non-prime order group like Edwards25519 is used instead of Ristretto255, the
verification function must account for co-factors to be strongly unforgeable.

```text
function Verify(signer.pub, message, I, s):
  state ← Initialize("com.example.eddsa")               // Initialize a protocol with a domain string.
  state ← Mix(state, signer.pub)                        // Mix the signer's public key into the protocol.
  state ← Mix(state, message)                           // Mix the message into the protocol.
  state ← Mix(state, I)                                 // Mix the commitment point into the protocol.
  (state, r') ← Ristretto255::Scalar(Derive(state, 64)) // Derive a counterfactual challenge scalar.
  I' ← [s]G - [r']signer.pub                            // Calculate the counterfactual commitment point.
  return I = I'                                         // The signature is valid if both points are equal.
```

An additional variation on this construction uses `Encrypt` instead of `Mix` to include the
commitment point `I` in the protocol's state. This makes it impossible to recover the signer's
public key from a message and signature (which may be desirable for privacy in some contexts) at the
expense of making batch verification impossible.

### Signcryption

Lockstitch can be used to integrate a [HPKE](#hybrid-public-key-encryption) scheme and
a [digital signature](#digital-signatures) scheme to produce a signcryption scheme, providing both
confidentiality and strong authentication in the public key setting:

```text
function Signcrypt(sender, receiver.pub, plaintext):
  ephemeral ← Ristretto255::KeyGen()
  state ← Initialize("com.example.signcrypt")            // Initialize a protocol with a domain string.
  state ← Mix(state, receiver.pub)                       // Mix the receiver's public key into the protocol.
  state ← Mix(state, sender.pub)                         // Mix the sender's public key into the protocol.
  state ← Mix(state, ephemeral.pub)                      // Mix the ephemeral public key into the protocol.
  state ← Mix(state, ECDH(receiver.pub, ephemeral.priv)) // Mix the ECDH shared secret into the protocol.
  (state, ciphertext) ← Encrypt(state, plaintext)        // Encrypt the plaintext.
  (k, I) ← Ristretto255::KeyGen()                        // Generate a commitment scalar and point.
  state ← Mix(state, I)                                  // Mix the commitment point into the protocol.
  (state, r) ← Ristretto255::Scalar(Derive(state, 64))   // Derive a challenge scalar.
  s ← signer.priv * r + k                                // Calculate the proof scalar.
  return (ephemeral.pub, ciphertext, I, s)               // Return the ephemeral public key, ciphertext, and signature.
```

```text
function Unsigncrypt(receiver, sender.pub, ephemeral.pub, I, s):
  state ← Initialize("com.example.signcrypt")            // Initialize a protocol with a domain string.
  state ← Mix(state, receiver.pub)                       // Mix the receiver's public key into the protocol.
  state ← Mix(state, sender.pub)                         // Mix the sender's public key into the protocol.
  state ← Mix(state, ephemeral.pub)                      // Mix the ephemeral public key into the protocol.
  state ← Mix(state, ECDH(ephemeral.pub, receiver.priv)) // Mix the ECDH shared secret into the protocol.
  (state, plaintext) ← Decrypt(state, ciphertext)        // Decrypt the ciphertext.
  state ← Mix(state, I)                                  // Mix the commitment point into the protocol.
  (state, r') ← Ristretto255::Scalar(Derive(state, 64))  // Derive a counterfactual challenge scalar.
  I' ← [s]G - [r']signer.pub                             // Calculate the counterfactual commitment point.
  if I = I':
    return plaintext                                     // If both points are equal, return the plaintext.
  else:
    return ⊥                                             // Otherwise, return an error.
```

Because Lockstitch is an incremental, stateful way of building protocols, this integrated
signcryption scheme is stronger than generic schemes which combine separate public key encryption
and digital signature algorithms: Encrypt-Then-Sign (`EtS`) and Sign-then-Encrypt (`StE`).

An adversary attacking an `EtS` scheme can strip the signature from someone else's encrypted message
and replace it with their own, potentially allowing them to trick the recipient into decrypting the
message for them. That's possible because the signature is of the ciphertext itself, which the
adversary knows. A standard Schnorr signature scheme like Ed25519 derives the challenge scalar `r`
from a hash of the signer's public key and the message being signed (i.e. the ciphertext).

With this scheme, on the other hand, the digital signature isn't of the ciphertext alone, but of all
inputs to the protocol. The challenge scalar `r` is derived from the protocol's state, which depends
on (among other things) the ECDH shared secret. Unless the adversary already knows the shared secret
(i.e. the secret key that the plaintext is encrypted with) they can't create their own signature
(which they're trying to do in order to trick someone into giving them the plaintext).

An adversary attacking an `StE` scheme can decrypt a signed message sent to them and re-encrypt it
for someone else, allowing them to pose as the original sender. This scheme makes simple replay
attacks impossible by including both the intended sender and receiver's public keys in the protocol
state. The initial [HPKE](#hybrid-public-key-encryption)-style portion of the protocol can be
trivially constructed by an adversary with an ephemeral key pair of their choosing, but the final
portion is the sUF-CMA secure [EdDSA-style Schnorr signature scheme](#digital-signatures) from the
previous section and unforgeable without the sender's private key.
