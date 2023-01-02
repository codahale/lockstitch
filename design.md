# The Design Of Lockstitch

Lockstitch provides a single cryptographic service for all symmetric-key operations and an
incremental, stateful building block for complex schemes, constructions, and protocols, all built on
top of SHA-256 and [Rocca-S][], an authenticated cipher.

[Rocca-S]: https://www.ietf.org/archive/id/draft-nakano-rocca-s-02.html

## Preliminaries

The basic unit of Lockstitch is the protocol, which wraps an SHA-256 instance.

### Encoding Operations

Each Lockstitch operation's inputs are encoded so that any two non-equal sequences of operations
produce non-equal encoded forms:

```text
function Process(state, input, op_code):
  state ← SHA256::Update(state, input)
  state ← SHA256::Update(state, TupleHash::RightEncode(|input|))
  state ← SHA256::Update(state, [op_code])
  return state
```

First, the protocol's state is updated with the operation's input. Second, the protocol's state is
updated with the length of that input encoded using the TupleHash `right_encode` function from
[NIST SP 800-185][]. Finally, the protocol's state is updated with a 1-byte code specific to the
type of operation which was performed.

[NIST SP 800-185]: https://www.nist.gov/publications/sha-3-derived-functions-cshake-kmac-tuplehash-and-parallelhash

This encoding ensures that operations of variable-length inputs are always unambiguously encoded.

### Generating Output

To generate any output during an operation, the protocol first finalizes its current SHA-256 state
into a 32-byte digest. That digest is used to key a chain Rocca-S instance, and two 32-byte keys are
derived from its PRF output. The protocol's state is replaced with a new SHA-256 instance and
updated with the first key; a Rocca-S instance is initialized with the second key using the
operation code as a nonce and used to generate any output:

```text
function Chain(state):
  D ← SHA256::Finalize(state)
  prf ← RoccaS::Init(D, [0x07; 16])
  K₀ǁK₁ ← RoccaS::PRF(prf , 64)
  state ← SHA256::Init()                    // Reset the state.
  state ← Process(state, K₀, 0x01)          // Update the protocol with the first key and the Init op code.
  output ← RoccaS::new(K₁, [operation; 16]) // Create an output Rocca-S instance with the second key.
  return state, output
```

**N.B.**: Each operation is limited to 2^125 bytes of output.

#### KDF Security

`Chain` uses an [HKDF][]-style _Extract-then-Expand_ key derivation function (KDF) with the
protocol's prior inputs (i.e. the [encoded](#encoding-operations) operations) as the effective
keying material, SHA-256 as the strong computational extractor for the keying material, and Rocca-S
as a PRF.

[HKDF]: https://www.rfc-editor.org/rfc/rfc5869.html

#### KDF Chains

Given that `Chain` is KDF secure and replaces the protocol's state with derived output, sequences of
Lockstitch operations which accept input and output in a protocol therefore constitute a [KDF
chain][kdf-chain], giving Lockstitch protocols the following security properties:

[kdf-chain]: https://signal.org/docs/specifications/doubleratchet/doubleratchet.pdf

* **Resilience**: A protocol's outputs will appear random to an adversary so long as one of the
  inputs is secret, even if the other inputs to the protocol are adversary-controlled.
* **Forward Security**: A protocol's previous outputs will appear random to an adversary even if the
  protocol's state is disclosed at some point.
* **Break-in Recovery**: A protocol's future outputs will appear random to an adversary in
  possession of the protocol's state as long as one of the future inputs to the protocol is secret.

Finally, assuming that Rocca-S is PRF secure, an adversary in possession of the output will not be
able to infer anything about the key or, indeed, distinguish the resulting output from a randomly
generated sequences of bytes of equal length.

## Operations

Lockstitch supports six operations: `Init`, `Mix`, `Derive`, `Encrypt`/`Decrypt`, `Seal`/`Open`, and
`Ratchet`.

### `Init`

Every protocol is initialized with a domain separation string, used to initialize an SHA-256
instance:

```text
function Init(domain):
  state ← SHA256::Init()               // Initialize a new SHA-256 instance.
  state ← Process(state, domain, 0x01) // Process the domain string as input with the Init op code.
  return state
```

The BLAKE3 recommendations for KDF context strings apply equally to Lockstitch protocol domains:

> The context string should be hardcoded, globally unique, and application-specific. … The context
> string should not contain variable data, like salts, IDs, or the current time. (If needed, those
> can be part of the key material, or mixed with the derived key afterwards.) … The purpose of this
> requirement is to ensure that there is no way for an attacker in any scenario to cause two
> different applications or components to inadvertently use the same context string. The safest way
> to guarantee this is to prevent the context string from including input of any kind.

### `Mix`

`Mix` takes a byte sequence of arbitrary length and makes the protocol's state dependent on it:

```text
function Mix(state, data):
  state ← Process(state, data, 0x02) // Process the data as input with the Mix op code.
  return state
```

Unlike inputs to a standard hash function, `Mix` operations (as with all other operations) are not
associative. That is, `Mix("alpha"); Mix("bet")` is not equivalent to `Mix("alphabet")`. This
eliminates the possibility of collisions; no additional padding or encoding is required.

Multiple `Mix` operations in a row are equivalent to a single [encoded](#encoding-operations) block
of input to SHA-256.  Unlike other operations (which all produce output and therefore replace the
state with derived output), `Mix` does not replace the hasher, allowing sequential `Mix` operations
to be batched, leveraging the full throughput potential of SHA-256.

**N.B.**: Processing more than 2^64 bytes without generating output will result in undefined
behavior.

### `Derive`

`Derive` produces a pseudo-random byte sequence of arbitrary length:

```text
function Derive(state, n):
  (state, output) ← Chain(state, 0x03)  // Ratchet the protocol state and key an output Rocca-S instance.
  prf ← RoccaS::PRF(output, n)          // Generate n bytes of Rocca-S PRF.
  state ← Process(state, LE64(n), 0x03) // Processes the output length with the Derive op code.
  return (state, prf) 
```

A `Derive` operation's output is indistinguishable from random by an adversary who does not know the
protocol's state prior to the operation provided SHA-256 is collision-resistant and RoccaS is PRF
secure. The protocol's state after the operation is dependent on both the fact that the operation
was a `Derive` operation as well as the number of bytes produced.

`Derive` supports streaming output, thus a shorter `Derive` operation will return a prefix of a
longer one (e.g.  `Derive(16)` and `Derive(32)` will share the same initial 16 bytes). Once the
operation is complete, however, the protocols' states will be different. If a use case requires
`Derive` output to be dependent on its length, include the length in a `Mix` operation beforehand.

### `Encrypt`/`Decrypt`

`Encrypt` uses Rocca-S to encrypt a given plaintext with a key derived from the protocol's current
state and updates the protocol's state with the final Rocca-S tag.

```text
function Encrypt(state, plaintext):
  (state, output) ← Chain(state, 0x04)            // Ratchet the protocol state and key an output Rocca-S instance.
  ciphertext ← RoccaS::Encrypt(output, plaintext) // Encrypt the plaintext with Rocca-S.
  tag ← RoccaS::Tag(output)                       // Calculate the Rocca-S tag.
  state ← Process(state, tag, 0x04)               // Process the tag as input.
  return (state, ciphertext)
```

`Decrypt` is used to decrypt the outputs of `Encrypt`.

```text
function Decrypt(state, ciphertext):
  (state, output) ← Chain(state, 0x04)            // Ratchet the protocol state and key an output Rocca-S instance.
  plaintext ← RoccaS::Decrypt(output, ciphertext) // Decrypt the plaintext with Rocca-S.
  tag ← RoccaS::Tag(output)                       // Calculate the Rocca-S tag.
  state ← Process(state, tag, 0x04)               // Process the tag as input.
  return (state, plaintext)
```

Three points bear mentioning about `Encrypt` and `Decrypt`.

First, both `Encrypt` and `Decrypt` use the same `Crypt` operation code to ensure protocols have
the same state after both encrypting and decrypting data.

Second, despite not updating the protocol state with either the plaintext or ciphertext, the
inclusion of the output tag ensures the protocol's state is dependent on both because Rocca-S is
compactly committing.

Third, `Crypt` operations provide no authentication by themselves. An attacker can modify a
ciphertext and the `Decrypt` operation will return a plaintext which was never encrypted. Alone,
they are EAV secure (i.e. a passive adversary will not be able to read plaintext without knowing the
protocol's prior state) but not IND-CPA secure (i.e. an active adversary with an encryption oracle
will be able to detect duplicate plaintexts) or IND-CCA secure (i.e. an active adversary can produce
modified ciphertexts which successfully decrypt). For IND-CPA and IND-CCA security,
use [`Seal`/`Open`](#sealopen).

As with `Derive`, `Encrypt`'s streaming support means an `Encrypt` operation with a shorter
plaintext produces a keystream which is a prefix of one with a longer plaintext (e.g.
`Encrypt("alpha")` and `Encrypt("alphabet")` will produce ciphertexts with the same initial 5
bytes). Once the operation is complete, however, the protocols' states would be different. If a use
case requires ciphertexts to be dependent on their length, include the length in a `Mix` operation
beforehand.

### `Seal`/`Open`

The `Seal` operation uses Rocca-S to encrypt a given plaintext with a key derived from the
protocol's current state, updates the protocol's state with the final Rocca-S tag, and returns the
ciphertext along with a truncated copy of the tag:

```text
function Seal(state, plaintext):
  (state, output) ← Chain(state, 0x05)            // Ratchet the protocol state and key an output Rocca-S instance.
  ciphertext ← RoccaS::Encrypt(output, plaintext) // Encrypt the plaintext with Rocca-S.
  tag ← RoccaS::Tag(output)                       // Calculate the Rocca-S tag.
  state ← Process(state, tag, 0x05)               // Process the tag as input.
  return (state, ciphertext, tag[..16])           // Return the ciphertext and the first half of the tag.
```

This is essentially the same thing as the `Encrypt` operation but includes the Rocca-S tag in the
ciphertext.

The `Open` operation decrypts the ciphertext and compares the counterfactual tag against the tag
included with the ciphertext:

```text
function Open(state, ciphertext, tag):
  (state, output) ← Chain(state, 0x05)            // Ratchet the protocol state and key an output Rocca-S instance.
  plaintext ← RoccaS::Decrypt(output, ciphertext) // Decrypt the plaintext with Rocca-S.
  tag′ ← RoccaS::Tag(output)                      // Calculate the counterfactual Rocca-S tag.
  state ← Process(state, tag′, 0x05)              // Process the tag as input.
  if tag ≠ tag′[..16]:                            // If the tags are equal, the plaintext is authentic.
    return ⟂ 
  else:
    return (state, plaintext) 
```

The resulting construction is CCA secure if Rocca-S is CCA secure.

### `Ratchet`

The `Ratchet` operation irreversibly modifies the protocol's state, preventing rollback:

```text
function Ratchet(state):
  (state, _) ← Chain(state, 0x06) // Ratchet the protocol state without generating output.
  state ← Process(state, ɛ, 0x06) // Process the empty string as input.
  return state
```

## Basic Protocols

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

This construction is collision-resistant if SHA-256 is collision-resistant.

### Message Authentication Codes

Adding a key to the previous construction makes it a MAC:

```text
function Mac(key, data):
  state ← Initialize("com.example.mac") // Initialize a protocol with a domain string.
  state ← Mix(state, key)               // Mix the key into the protocol.
  state ← Mix(state, data)              // Mix the data into the protocol.
  (state, tag) ← Derive(state, 16)      // Derive 16 bytes of output and return it.
  return tag
```

The [operation encoding](#encoding-operations) ensures that the key and the data will never overlap,
even if their lengths vary.

Use a constant-time comparison to verify the MAC:

```text
function VerifyMac(key, data, tag):
  state ← Initialize("com.example.mac") // Initialize a protocol with a domain string.
  state ← Mix(state, key)               // Mix the key into the protocol.
  state ← Mix(state, data)              // Mix the data into the protocol.
  (state, tag′) ← Derive(state, 16)     // Derive 16 bytes of output.
  return tag = tag′
```

### Authenticated Encryption And Data (AEAD)

Lockstitch can be used to create an AEAD:

```text
function Seal(key, nonce, ad, plaintext):
  state ← Initialize("com.example.aead")            // Initialize a protocol with a domain string.
  state ← Mix(state, key)                           // Mix the key into the protocol.
  state ← Mix(state, nonce)                         // Mix the nonce into the protocol.
  state ← Mix(state, ad)                            // Mix the associated data into the protocol.
  (state, ciphertext, tag) ← Seal(state, plaintext) // Seal the plaintext.
  return ciphertext, tag                            // Return the ciphertext and tag.
```

The introduction of a nonce makes the scheme probabilistic (which is required for IND-CCA security).
The final `Seal` operation closes over all inputs--key, nonce, associated data, and plaintext--which
are also the values used to produce the ciphertext. Forging a tag here would imply that Rocca-S's
MAC construction is not sUF-CMA secure.

In addition, this construction is compactly committing: finding a ciphertext and tag pair which
successfully decrypts under multiple keys would imply that Rocca-S is not compactly committing, and
the final tag serves as a commitment for the ciphertext.

Decryption uses the `Open` operation to decrypt:

```text
function Open(key, nonce, ad, ciphertext, tag):
  state ← Initialize("com.example.aead")            // Initialize a protocol with a domain string.
  state ← Mix(state, key)                           // Mix the key into the protocol.
  state ← Mix(state, nonce)                         // Mix the nonce into the protocol.
  state ← Mix(state, ad)                            // Mix the associated data into the protocol.
  (state, plaintext) ← Open(state, ciphertext, tag) // Open the ciphertext.
  return plaintext                                  // Return the authenticated plaintext or ⟂.
```

Unlike a standard AEAD, this can be easily extended to allow for multiple, independent pieces of
associated data.

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
  (state, ciphertext) ← Seal(state, plaintext)           // Seal the plaintext.
  return (ephemeral.pub, ciphertext)                     // Return the ephemeral public key and tag.
```

```text
function HPKE_Decrypt(receiver, ephemeral.pub, ciphertext, tag):
  state ← Initialize("com.example.hpke")                 // Initialize a protocol with a domain string.
  state ← Mix(state, receiver.pub)                       // Mix the receiver's public key into the protocol.
  state ← Mix(state, ephemeral.pub)                      // Mix the ephemeral public key into the protocol.
  state ← Mix(state, ECDH(ephemeral.pub, receiver.priv)) // Mix the ephemeral ECDH shared secret into the protocol.
  (state, plaintext) ← Open(state, ciphertext)           // Open the plaintext.
  return plaintext                                       // Return the authenticated plaintext or ⟂.
```

**N.B.:** This construction does not provide authentication in the public key setting. An adversary
in possession of the receiver's public key (i.e. anyone) can create ciphertexts which will decrypt
as valid. In the symmetric key setting (i.e. an adversary without the receiver's public key), this
is IND-CCA secure, but the real-world scenarios in which that applies are minimal. As-is, the tag
is more like a checksum than a MAC, preventing modifications only by adversaries who don't have the
recipient's public key.

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
  (state, r′) ← Ristretto255::Scalar(Derive(state, 64)) // Derive a counterfactual challenge scalar.
  I′ ← [s]G - [r′]signer.pub                            // Calculate the counterfactual commitment point.
  return I = I′                                         // The signature is valid if both points are equal.
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
  (state, r′) ← Ristretto255::Scalar(Derive(state, 64))  // Derive a counterfactual challenge scalar.
  I′ ← [s]G - [r′]signer.pub                             // Calculate the counterfactual commitment point.
  if I = I′:
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

### Hedged Ephemeral Values

Many cryptographic schemes require unique, ephemeral values, often with grave consequences should
those values not be unique. A key and nonce pair, when used to encrypt two different plaintexts,
will lose confidentiality. A commitment scalar, when used to sign two different messages, will leak
the private key. Some algorithms (e.g. AES-SIV or Ed25519) derive those ephemeral values from secret
information in a deterministic way: AES-SIV derives a nonce from the key, associated data, and
plaintext; Ed25519 derives a commitment scalar from the signer's private key and the message. This
has the benefit of eliminating nonce-misuse but can have unintended consequences. Deterministic
encryption and signing can leak information about duplicate messages to eavesdroppers and is
vulnerable to power-analysis side channels.

A happy medium between these two extremes is the "hedged ephemeral" strategy, which combines both
secret information _and_ random values to generate ephemeral values. In the event of an RNG failure,
they devolve to be deterministic and safe.

To generate hedged values, a Lockstitch protocol can be cloned, mixed with secret values and a
random value, and used to derive a hedged ephemeral:

```text
function HedgedSign(signer, message):
  state ← Initialize("com.example.eddsa")              // Initialize a protocol with a domain string.
  state ← Mix(state, signer.pub)                       // Mix the signer's public key into the protocol.
  state ← Mix(state, message)                          // Mix the message into the protocol.
  with clone ← Clone(state) do                         // Clone the protocol's state.
    clone ← Mix(clone, signer.priv)                    // Mix the signer's private key into the clone.
    clone ← Mix(clone, Rand(64))                       // Mix 64 random bytes into the clone.
    k ← Ristretto255::Scalar(Derive(clone, 64))        // Derive a commitment scalar from the clone.
    I ← [k]G                                           // Calculate the commitment point.
    yield (k, I)                                       // Return the ephemeral key pair to the signing scope.
  end                                                  // Discard the cloned state.
  state ← Mix(state, I)                                // Mix the commitment point into the protocol.
  (state, r) ← Ristretto255::Scalar(Derive(state, 64)) // Derive a challenge scalar.
  s ← signer.priv * r + k                              // Calculate the proof scalar.
  return (I, s)                                        // Return the commitment point and proof scalar.
```
