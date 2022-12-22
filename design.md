# The Design Of Lockstitch

Lockstitch provides a single cryptographic primitive for all symmetric-key operations and an
incremental, stateful building block for complex schemes, constructions, and protocols.

## Preliminaries

The overall structure of Lockstitch is inspired by the Stateful Hash Object scheme in Section 6.3 of
[the BLAKE3 spec][blake3] and the [KDF chain][kdf-chain] of the Signal protocol. Lockstitch's
interface is inspired by [STROBE][strobe] and [Xoodyak][xoodyak].

[blake3]: https://blake3.io
[strobe]: https://strobe.sourceforge.io
[xoodyak]: https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/xoodyak-spec-final.pdf

### Initializing A Protocol

The basic unit of Lockstitch is the protocol, which wraps a BLAKE3 hasher. Every protocol is
initialized with a domain separation string, used to initialize a BLAKE3 hasher in key derivation
function (KDF) mode:

```text
function Initialize(domain):
  state ← BLAKE3::KDF(domain)
  return state
```

The BLAKE3 recommendations for KDF context strings apply equally to Lockstitch protocol domains:

> The context string should be hardcoded, globally unique, and application-specific. … The context
> string should not contain variable data, like salts, IDs, or the current time. (If needed, those
> can be part of the key material, or mixed with the derived key afterwards.) … The purpose of this
> requirement is to ensure that there is no way for an attacker in any scenario to cause two
> different applications or components to inadvertently use the same context string. The safest way
> to guarantee this is to prevent the context string from including input of any kind.

### Encoding An Operation

Given a BLAKE3 hasher, Lockstitch defines an unambiguous encoding for operations (similar to
TupleHash). Each operation updates the protocol's state with operation-specific data or replaces it
with a derivative state. Once an operation is complete, the protocol's state is updated with the
number of bytes processed `n` (encoded with TupleHash's `right_encode` function) and the operation's
1-byte code:

```text
state ← BLAKE3::Update(state, RE(n))
state ← BLAKE3::Update(state, [operation])
```

This allows for the unambiguous encoding of multiple inputs and different types of operations as
well as operations which produce outputs but do not directly update the protocol's state.

**N.B.**: Hashing more than 2^69 bytes with BLAKE3 will result in undefined behavior.

### Generating Output

To generate any output during an operation, the protocol produces a 32-byte chain key and a 16-byte
output key from the first 48 bytes of XOF output from its BLAKE3 hasher. The protocol then replaces
its BLAKE3 hasher with a BLAKE3 keyed hasher using the first key. Finally, an AEGIS128L instance is
initialized using the output key and a 128-bit nonce consisting of the operation's 1-byte code
repeated 16 times.

```text
K₀ǁK₁ ← BLAKE3::XOF(state, 48)
state ← BLAKE3::Keyed(K₀)
aegis ← AEGIS128L::new(K₁, [operation; 16])
```

**N.B.**: Each operation is limited to 2 EiB of output (2^64 bits).

If BLAKE3 is KDF secure (i.e. its outputs are indistinguishable from random by an adversary in
possession of all inputs except the keying material, which is not required to be uniformly random),
then sequences of operations which accept input and output in a protocol form a [KDF
chain][kdf-chain], giving Lockstitch protocols the following security properties:

* **Resilience**: A protocol's outputs will appear random to an adversary so long as one of the
  inputs is secret, even if the other inputs to the protocol are adversary-controlled.
* **Forward Security**: A protocol's previous outputs will appear random to an adversary even if the
  protocol's state is disclosed at some point.
* **Break-in Recovery**: A protocol's future outputs will appear random to an adversary in
  possession of the protocol's state as long as one of the future inputs to the protocol is secret.

[kdf-chain]: https://signal.org/docs/specifications/doubleratchet/doubleratchet.pdf

Finally, if AEGIS128L is PRF secure (i.e. its outputs are indistinguishable from random by an
adversary if the key is uniformly random), an adversary in possession of the output will not be able
to infer anything about the key or, indeed, distinguish the output from a randomly generated
sequences of bytes of equal length.

#### XOF vs PRF

While BLAKE can produce output of arbitrary length via its eXtendable Output Function (XOF),
Lockstitch uses AEGIS128L exclusively to generate output values. This is done for three reasons.

First, this design provides a clean separation of responsibilities. BLAKE3 effectively functions as
a chained KDF, a task for which it was designed and for which its fitness can be clearly analyzed.
AEGIS128L is used as a pseudo-random function (PRF), the task for which it was designed.

Second, in addition to a key, AEGIS128L requires a nonce which is copied directly into the cipher's
initial state. The use of the operation code in the nonce ensures that the output of an operation is
dependent on both the protocol's state prior to that operation as well as the intent of the current
operation and does so without requiring an additional BLAKE3 update. Because the key is derived from
the protocol's state and assumed to be unique, the nonce can be used to encode intent without risk
of key/nonce pair re-use.

Finally, the use of AEGIS128L provides a performance benefit due to the use of hardware AES
instructions. On x86-64 or Apple Silicon processors, AEGIS128L will top 10 GB/s of output, more than
10x faster than BLAKE3's XOF output.

## Operations

Lockstitch supports five operations: `Mix`, `Derive`, `Encrypt`/`Decrypt`, `Seal`/`Open`, and
`Ratchet`.

### `Mix`

`Mix` takes a byte sequence of arbitrary length and makes the protocol's state dependent on it:

```text
function Mix(state, data):
  state ← BLAKE3::Update(state, data)         // Update the protocol's state with the data.
  state ← BLAKE3::Update(state, RE(|data|))   // Update the protocol's state with the data's length.
  state ← BLAKE3::Update(state, [0x01])       // Update the protocol's state with the Mix op code.
  return state
```

Unlike a standard hash function, `Mix` operations (as with all other operations) are not
associative. That is, `Mix("alpha"); Mix("bet")` is not equivalent to `Mix("alphabet")`. This
eliminates the possibility of collisions; no additional padding or encoding is required.

`Mix` consists solely of BLAKE3 update operations and as such has collision resistance which reduces
to the underlying BLAKE3 algorithm: no polynomial algorithm should be able to find two sets of
inputs which produce the same output except with negligible probability.

Unlike other operations (which all produce output and therefore replace the BLAKE3 hasher with a
derived hasher), `Mix` does not replace the hasher, allowing sequential `Mix` operations to be
batched, leveraging the full throughput potential of BLAKE3.

### `Derive`

`Derive` produces a pseudo-random byte sequence of arbitrary length:

```text
function Derive(state, n):
  K₀ǁK₁ ← BLAKE3::XOF(state, 48)             // Generate two keys with XOF output from the current state.
  state ← BLAKE3::Keyed(K₀)                  // Replace the protocol's state with a new keyed hasher.
  aegis ← AEGIS128L::new(K₁, [0x02; 16])     // Key an AEGIS128L instance using the operation code as a nonce.
  prf ← AEGIS128L::Encrypt(aegis, [0x00; n]) // Produce n bytes of AEGIS128L output.
  tag ← AEGIS128L::Finalize(aegis)           // Calculate the AEGIS128L tag.
  state ← BLAKE3::Update(state, tag)         // Update the protocol's state with the tag.
  state ← BLAKE3::Update(state, RE(16))      // Update the protocol's state with the tag length.
  state ← BLAKE3::Update(state, [0x02])      // Update the protocol's state with the Derive op code.
  return (state, prf) 
```

A `Derive` operation's output is indistinguishable from random by an adversary who does not know the
protocol's state prior to the operation provided BLAKE3 is KDF secure and AEGIS128L is PRF secure.
The protocol's state after the operation is dependent on both the fact that the operation was a
`Derive` operation as well as the number of bytes produced. AEGIS128L is compactly committing by
design, so the final `tag` closes over the key, the nonce, and the plaintext (in this case, `n` zero
bytes).

`Derive` supports streaming output, thus a shorter `Derive` operation will return a prefix of a
longer one (e.g.  `Derive(16)` and `Derive(32)` will share the same initial 16 bytes). Once the
operation is complete, however, the protocols' states will be different.. If a use case requires
`Derive` output to be dependent on its length, include the length in a `Mix` operation beforehand.

### `Encrypt`/`Decrypt`

`Encrypt` uses AEGIS128L to encrypt a given plaintext with a key derived from the protocol's current
state and updates the protocol's state with the final AEGIS128L tag.

```text
function Encrypt(state, plaintext):
  K₀ǁK₁ ← BLAKE3::XOF(state, 48)                    // Generate two keys with XOF output from the current state.
  state ← BLAKE3::Keyed(K₀)                         // Replace the protocol's state with a new keyed hasher.
  aegis ← AEGIS128L::new(K₁, [0x03; 16])            // Key an AEGIS128L instance using the operation code as a nonce.
  ciphertext ← AEGIS128L::Encrypt(aegis, plaintext) // Encrypt the plaintext with AEGIS128L.
  tag ← AEGIS128L::Finalize(aegis)                  // Calculate the AEGIS128L tag.
  state ← BLAKE3::Update(state, tag)                // Update the protocol's state with the tag.
  state ← BLAKE3::Update(state, RE(16))             // Update the protocol's state with the tag length.
  state ← BLAKE3::Update(state, [0x03])             // Update the protocol's state with the Crypt op code.
  return (state, ciphertext) 
```

`Decrypt` is used to decrypt the outputs of `Encrypt`.

```text
function Decrypt(state, ciphertext):
  K₀ǁK₁ ← BLAKE3::XOF(state, 48)                    // Generate two keys with XOF output from the current state.
  state ← BLAKE3::Keyed(K₀)                         // Replace the protocol's state with a new keyed hasher.
  aegis ← AEGIS128L::new(K₁, [0x03; 16])            // Key an AEGIS128L instance using the operation code as a nonce.
  plaintext ← AEGIS128L::Decrypt(aegis, ciphertext) // Decrypt the ciphertext with AEGIS128L.
  tag ← AEGIS128L::Finalize(aegis)                  // Calculate the AEGIS128L tag.
  state ← BLAKE3::Update(state, tag)                // Update the protocol's state with the tag.
  state ← BLAKE3::Update(state, RE(16))             // Update the protocol's state with the tag length.
  state ← BLAKE3::Update(state, [0x03])             // Update the protocol's state with the Crypt op code.
  return (state, plaintext) 
```

Three points bear mentioning about `Encrypt` and `Decrypt`.

First, both `Encrypt` and `Decrypt` use the same `Crypt` operation code to ensure protocols have
the same state after both encrypting and decrypting data.

Second, despite not updating the BLAKE3 hasher with either the plaintext or ciphertext, the
inclusion of the AEGIS128L tag ensures the protocol's state is dependent on both.

Third, `Crypt` operations provide no authentication by themselves. An attacker can modify a
ciphertext and the `Decrypt` operation will return a plaintext which was never encrypted. Alone,
they are EAV secure (i.e. a passive adversary will not be able to read plaintext without knowing the
protocol's prior state) but not IND-CPA secure (i.e. an active adversary with an encryption oracle
will be able to detect duplicate plaintexts) or IND-CCA secure (i.e. an active adversary can produce
modified ciphertexts which successfully decrypt). For IND-CPA and IND-CCA security,
`Encrypt`/`Decrypt` operations must be part of an integrated protocol (e.g. an
[AEAD](#authenticated-encryption-and-data-aead)).

As with `Derive`, `Encrypt`'s streaming support means an `Encrypt` operation with a shorter
plaintext produces a keystream which is a prefix of one with a longer plaintext (e.g.
`Encrypt("alpha")` and `Encrypt("alphabet")` will produce ciphertexts with the same initial 5
bytes). Once the operation is complete, however, the protocols' states would be different. If a use
case requires ciphertexts to be dependent on their length, include the length in a `Mix` operation
beforehand.

### `Seal`/`Open`

The `Seal` operation uses AEGIS128L to encrypt a given plaintext with a key derived from the
protocol's current state, updates the protocol's state with the final AEGIS128L tag, and returns the
tag:

```text
function Seal(state, plaintext):
  K₀ǁK₁ ← BLAKE3::XOF(state, 48)                    // Generate two keys with XOF output from the current state.
  state ← BLAKE3::Keyed(K₀)                         // Replace the protocol's state with a new keyed hasher.
  aegis ← AEGIS128L::new(K₁, [0x04; 16])            // Key an AEGIS128L instance using the operation code as a nonce.
  ciphertext ← AEGIS128L::Encrypt(aegis, plaintext) // Encrypt the plaintext with AEGIS128L.
  tag ← AEGIS128L::Finalize(aegis)                  // Calculate the AEGIS128L tag.
  state ← BLAKE3::Update(state, tag)                // Update the protocol's state with the tag.
  state ← BLAKE3::Update(state, RE(16))             // Update the protocol's state with the tag length.
  state ← BLAKE3::Update(state, [0x04])             // Update the protocol's state with the Crypt op code.
  return (state, ciphertextǁtag) 
```

This is essentially the same thing as the `Encrypt` operation but includes the AEGIS128L tag in the
ciphertext.

The `Open` operation decrypts the ciphertext and compares the counterfactual tag against the tag
included with the ciphertext:

```text
function Open(state, ciphertextǁtag):
  K₀ǁK₁ ← BLAKE3::XOF(state, 48)                    // Generate two keys with XOF output from the current state.
  state ← BLAKE3::Keyed(K₀)                         // Replace the protocol's state with a new keyed hasher.
  aegis ← AEGIS128L::new(K₁, [0x03; 16])            // Key an AEGIS128L instance using the operation code as a nonce.
  plaintext ← AEGIS128L::Decrypt(aegis, ciphertext) // Decrypt the ciphertext with AEGIS128L.
  tag′ ← AEGIS128L::Finalize(aegis)                 // Calculate the AEGIS128L tag.
  state ← BLAKE3::Update(state, tag′)               // Update the protocol's state with the tag.
  state ← BLAKE3::Update(state, RE(16))             // Update the protocol's state with the tag length.
  state ← BLAKE3::Update(state, [0x03])             // Update the protocol's state with the Crypt op code.
  if tag ≠ tag′:
    return ⟂ 
  return (state, plaintext) 
```

### `Ratchet`

The `Ratchet` operation irreversibly modifies the protocol's state, preventing rollback:

```text
function Ratchet(state):
  K ← BLAKE3::XOF(state, 32)            // Generate one key with XOF output from the current state.
  state ← BLAKE3::Keyed(K)              // Replace the protocol's state with a new keyed hasher.
  state ← BLAKE3::Update(state, RE(0))  // Update the protocol's state with zero bytes processed.
  state ← BLAKE3::Update(state, [0x05]) // Update the protocol's state with the Ratchet op code.
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

This is essentially equivalent to using BLAKE3 with AEGIS128L's MAC as an XOF. As such, it inherits
BLAKE3's collision resistance.

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

The [operation encoding](#encoding-an-operation) ensures that the key and the data will never
overlap, even if their lengths vary.

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
  state ← Initialize("com.example.aead")          // Initialize a protocol with a domain string.
  state ← Mix(state, key)                         // Mix the key into the protocol.
  state ← Mix(state, nonce)                       // Mix the nonce into the protocol.
  state ← Mix(state, ad)                          // Mix the associated data into the protocol.
  (state, ciphertext) ← Seal(state, plaintext)    // Seal the plaintext.
  return ciphertext                               // Return the ciphertext.
```

The introduction of a nonce makes the scheme probabilistic (which is required for IND-CCA security).
The final `Seal` operation closes over all inputs--key, nonce, associated data, and plaintext--which
are also the values used to produce the ciphertext. Forging a tag here would imply that AEGIS128L's
MAC construction is not sUF-CMA secure.

In addition, this construction is compactly committing: finding a ciphertext and tag pair which
successfully decrypts under multiple keys would imply either BLAKE3 is not collision-resistant or
AEGIS128L is not compactly committing, and the final tag serves as a commitment for the ciphertext.

Decryption uses the `Open` operation to decrypt:

```text
function Open(key, nonce, ad, ciphertext):
  state ← Initialize("com.example.aead")          // Initialize a protocol with a domain string.
  state ← Mix(state, key)                         // Mix the key into the protocol.
  state ← Mix(state, nonce)                       // Mix the nonce into the protocol.
  state ← Mix(state, ad)                          // Mix the associated data into the protocol.
  (state, plaintext) ← Open(state, ciphertext)    // Decrypt the ciphertext.
  return plaintext                                // Return the authenticated plaintext or ⟂.
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
