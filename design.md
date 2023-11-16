# The Design Of Lockstitch

Lockstitch provides a single cryptographic service for all symmetric-key operations and an
incremental, stateful building block for complex schemes, constructions, and protocols, all built on
top of SHA-256 and [AEGIS-128L][], an authenticated cipher.

[AEGIS-128L]: https://www.ietf.org/archive/id/draft-irtf-cfrg-aegis-aead-05.html

## Protocol

The basic unit of Lockstitch is the protocol, which encapsulates a transcript of encoded inputs.

A Lockstitch protocol supports the following operations:

* `Mix`, which makes all future output cryptographically dependent on a given labeled input.
* `Init`, which initializes a protocol with a domain separation string.
* `Ratchet`, which ratchets the protocol state and optionally keys an AEGIS-128L instance.
* `Derive`, which produces a bitstring of arbitrary length that is cryptographically dependent on
  all previous inputs.
* `Encrypt`/`Decrypt`, which encrypt and decrypt a message, making the protocol cryptographically
  dependent on the message.
* `Seal`/`Open`, which seal and open a message, making the protocol cryptographically dependent on
  the message.

Labels are used for all Lockstitch operations (except `Init` and `Ratchet`) to provide domain
separation of inputs and outputs.

### `Mix`

A `Mix` operation accepts a label and an input, encodes them, and appends them to the protocol's
transcript along with a constant operation code:

```text
function Mix(transcript, label, input):
  transcript ǁ 0x01 ǁ left_encode(|label|) ǁ label ǁ input ǁ right_encode(|input|)
```

`Mix` encodes the length of the label in bits and the length of the input in bits using
`left_encode` and `right_encode` from [NIST SP 800-185][], respectively. This ensures an unambiguous
encoding for any combination of label and input, regardless of length. `right_encode` is used for
the length of the input to support incremental processing of data streams whose sizes are not known
in advance.

**N.B.**: Processing more than 2^64 bytes without generating output will result in undefined
behavior.

### `Init`

An `Init` operation uses `Init` to initialize a Lockstitch protocol with a domain separation string:

```text
function Init(domain):
  0x02 ǁ Mix(ɛ, "domain", domain)
```

The BLAKE3 recommendations for KDF context strings apply equally to Lockstitch protocol domains:

> The context string should be hardcoded, globally unique, and application-specific. … The context
> string should not contain variable data, like salts, IDs, or the current time. (If needed, those
> can be part of the key material, or mixed with the derived key afterwards.) … The purpose of this
> requirement is to ensure that there is no way for an attacker in any scenario to cause two
> different applications or components to inadvertently use the same context string. The safest way
> to guarantee this is to prevent the context string from including input of any kind.

### `Ratchet`

A `Ratchet` operation replaces the protocol's transcript with a single `Mix` operation with a
derived key of the previous transcript as input and optionally keys an AEGIS-128L instance for
processing input and producing output.

```text
function Ratchet(transcript):
  K₀ǁN₀ ← sha256(transcript ǁ 0x03)
  HǁK₁ǁN₁ ← aegis128l::prf(K₀, N₀, 64)
  transcript ← Mix(ɛ, "chain-key", H) 
  output ← aegis128l::new(K₁, N₁)
  (transcript, output)
```

#### KDF Security

`Ratchet` uses an [HKDF][]-style _Extract-then-Expand_ key derivation function (KDF) with the
protocol's transcript as the effective keying material, SHA-256 as the strong computational
extractor for the keying material and AEGIS-128L as the expanding PRF.

[HKDF]: https://www.rfc-editor.org/rfc/rfc5869.html

#### KDF Chains

Given that `Ratchet` is KDF secure and replaces the protocol's state with derived output, sequences
of Lockstitch operations which accept input and output in a protocol therefore constitute a [KDF
chain][], giving Lockstitch protocols the following security properties:

[KDF chain]: https://signal.org/docs/specifications/doubleratchet/doubleratchet.pdf

* **Resilience**: A protocol's outputs will appear random to an adversary so long as one of the
  inputs is secret, even if the other inputs to the protocol are adversary-controlled.
* **Forward Security**: A protocol's previous outputs will appear random to an adversary even if the
  protocol's state is disclosed at some point.
* **Break-in Recovery**: A protocol's future outputs will appear random to an adversary in
  possession of the protocol's state as long as one of the future inputs to the protocol is secret.

### `Derive`

A `Derive` operation ratchets the protocol's state and produces a given number of bytes of PRF
output, including the number of bytes produced via a `Mix` operation.

```text
function Derive(transcript, label, n):
  (transcript, output) ← Ratchet(transcript ǁ 0x04 ǁ left_encode(|label|) ǁ label) 
  prf ← aegis128l::prf(output, n)
  transcript ← Mix(transcript, "len", left_encode(n))
  (transcript, prf)
```

A `Derive` operation's output is indistinguishable from random by an adversary who does not know the
protocol's state prior to the operation provided SHA-256 is collision-resistant and AEGIS-128L is
PRF secure. The protocol's state after the operation is dependent on both the fact that the
operation was a `Derive` operation as well as the number of bytes produced.

`Derive` supports streaming output, thus a shorter `Derive` operation will return a prefix of a
longer one (e.g.  `Derive("a", 16)` and `Derive("a", 32)` will share the same initial 16 bytes).
Once the operation is complete, however, the protocols' states will be different. If a use case
requires `Derive` output to be dependent on its length, include the length in a `Mix` operation
beforehand.

**N.B.**: Each operation is limited to 2^61 bytes of output.

### `Encrypt`/`Decrypt`

`Encrypt` and `Decrypt` operations ratchet the protocol's state, encrypt or decrypt an input with
AEGIS-128L, and include the AEGIS-128L tag via a `Mix` operation.

```text
function Encrypt(transcript, label, p):
  (transcript, output) ← Ratchet(transcript ǁ 0x05 ǁ left_encode(|label|) ǁ label) 
  cǁt ← aegis128l::encrypt(output, p)
  transcript ← Mix(transcript, "tag", t)
  (transcript, c)

function Decrypt(transcript, label, c):
  (transcript, output) ← Ratchet(transcript ǁ 0x05 ǁ left_encode(|label|) ǁ label) 
  pǁt ← aegis128l::decrypt(output, c)
  transcript ← Mix(transcript, "tag", t)
  (transcript, c)
```

Three points bear mentioning about `Encrypt` and `Decrypt`.

First, both `Encrypt` and `Decrypt` use the same operation code to ensure protocols have the same
state after both encrypting and decrypting data.

Second, despite not updating the protocol state with either the plaintext or ciphertext, the
inclusion of the long tag ensures the protocol's state is dependent on both because AEGIS-128L is
key committing (i.e. the probability of an attacker finding a different key, nonce, or plaintext
which produces the same authentication tag is negligible).

**N.B.:** AEGIS-128L by itself is not fully committing, as [tag collisions can be found if
authenticated data is attacker-controlled](https://eprint.iacr.org/2023/1495.pdf). Lockstitch does
not pass authenticated data to AEGIS-128L, however, mooting this type of attack.

Third, `Encrypt` operations provide no authentication by themselves. An attacker can modify a
ciphertext and the `Decrypt` operation will return a plaintext which was never encrypted. Alone,
they are EAV secure (i.e. a passive adversary will not be able to read plaintext without knowing the
protocol's prior state) but not IND-CPA secure (i.e. an active adversary with an encryption oracle
will be able to detect duplicate plaintexts) or IND-CCA secure (i.e. an active adversary can produce
modified ciphertexts which successfully decrypt). For IND-CPA and IND-CCA security, use
[`Seal`/`Open`](#sealopen).

As with `Derive`, `Encrypt`'s streaming support means an `Encrypt` operation with a shorter
plaintext produces a keystream which is a prefix of one with a longer plaintext (e.g.  `Encrypt("0",
"alpha")` and `Encrypt("0", "alphabet")` will produce ciphertexts with the same initial 5 bytes).
Once the operation is complete, however, the protocols' states would be different. If a use case
requires ciphertexts to be dependent on their length, include the length in a `Mix` operation
beforehand.

### `Seal`/`Open`

`Seal` and `Open` operations combine an `Encrypt` operation with a `Derive` operation to provide
authenticated encryption, returning a ciphertext and an authentication tag.

```text
function Seal(transcript, label, p):
  (transcript, c) ← Encrypt(transcript ǁ 0x06 ǁ left_encode(|label|) ǁ label, "message", p) 
  (transcript, t) ← Derive(transcript, "tag", 16)
  (c, t)

function Open(transcript, label, c, t):
  (transcript, p) ← Decrypt(transcript ǁ 0x06 ǁ left_encode(|label|) ǁ label, "message", c) 
  (transcript, t′) ← Derive(transcript, "tag", 16)
  if t = t′:
    return p
  else:
    return ⊥
```

## Basic Protocols

By combining operations, we can use Lockstitch to construct a wide variety of cryptographic schemes
using a single protocol.

### Message Digests

Calculating a message digest is as simple as a `Mix` and a `Derive`:

```text
function MessageDigest(message):
  md ← Init("com.example.md")            // Initialize a protocol with a domain string.
  md ← Mix(md, "message", data)          // Mix the message into the protocol.
  (_, digest) ← Derive(md, "digest", 32) // Derive 32 bytes of output and return it.
  return digest
```

This construction is collision-resistant if SHA-256 is collision-resistant.

### Message Authentication Codes

Adding a key to the previous construction makes it a MAC:

```text
function Mac(key, message):
  mac ← Init("com.example.mac")      // Initialize a protocol with a domain string.
  mac ← Mix(mac, "key", key)         // Mix the key into the protocol.
  mac ← Mix(mac, "message", message) // Mix the message into the protocol.
  (_, tag) ← Derive(mac, "tag", 16)  // Derive 16 bytes of output and return it.
  return tag
```

The use of labels and the encoding of [`Mix` inputs](#mix) ensures that the key and the message will
never overlap, even if their lengths vary.

Use a constant-time comparison to verify the MAC:

```text
function VerifyMac(key, message, tag):
  mac ← Init("com.example.mac")      // Initialize a protocol with a domain string.
  mac ← Mix(mac, "key", key)         // Mix the key into the protocol.
  mac ← Mix(mac, "message", message) // Mix the data into the protocol.
  (_, tag′) ← Derive(mac, "tag", 16) // Derive 16 bytes of output.
  return tag = tag′
```

### Authenticated Encryption And Data (AEAD)

Lockstitch can be used to create an AEAD:

```text
function Seal(key, nonce, ad, plaintext):
  aead ← Init("com.example.aead")                    // Initialize a protocol with a domain string.
  aead ← Mix(aead, "key", key)                       // Mix the key into the protocol.
  aead ← Mix(aead, "nonce", nonce)                   // Mix the nonce into the protocol.
  aead ← Mix(aead, "ad", ad)                         // Mix the associated data into the protocol.
  (_, ciphertext) ← Seal(aead, "message", plaintext) // Seal the plaintext.
  return ciphertext
```

The introduction of a nonce makes the scheme probabilistic (which is required for IND-CCA security).

Unlike many standard AEADs (e.g. AES-GCM and ChaCha20Poly1305), it is fully context-committing: the
tag is a strong cryptographic commitment to all the inputs. Similar to the
[CTX construction](https://par.nsf.gov/servlets/purl/10391723), which replaces the tag of an
existing AEAD with `H(K, N, A, T)`, the final `Seal` operation closes over all inputs--key, nonce,
associated data, and plaintext--which are also the values used to produce the ciphertext. Finding a
pair of `(key, nonce, ad, plaintext)` tuples which produce the same tag would similarly imply a lack
of UF-CMA security for AEGIS-128L or collision resistance for SHA-256.

Also unlike a standard AEAD, this can be easily extended to allow for multiple, independent pieces
of associated data without risk of ambiguous inputs.

```text
function Open(key, nonce, ad, ciphertext):
  aead ← Init("com.example.aead")                    // Initialize a protocol with a domain string.
  aead ← Mix(aead, "key", key)                       // Mix the key into the protocol.
  aead ← Mix(aead, "nonce", nonce)                   // Mix the nonce into the protocol.
  aead ← Mix(aead, "ad", ad)                         // Mix the associated data into the protocol.
  (_, plaintext) ← Open(aead, "message", ciphertext) // Open the ciphertext.
  return plaintext                                   // If both tags are equal, return the plaintext.
```

## Complex Protocols

Given an elliptic curve group like NIST P-256, Lockstitch can be used to build complex protocols
which integrate public- and symmetric-key operations.

### Hybrid Public-Key Encryption

Lockstitch can be used to build an integrated
[ECIES](https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme)-style public key encryption
scheme:

```text
function HPKE_Encrypt(receiver.pub, plaintext):
  ephemeral ← P256::KeyGen()                                   // Generate an ephemeral key pair.
  hpke ← Init("com.example.hpke")                              // Initialize a protocol with a domain string.
  hpke ← Mix(hpke, "receiver", receiver.pub)                   // Mix the receiver's public key into the protocol.
  hpke ← Mix(hpke, "ephemeral", ephemeral.pub)                 // Mix the ephemeral public key into the protocol.
  hpke ← Mix(hpke, "ecdh", ECDH(receiver.pub, ephemeral.priv)) // Mix the ephemeral ECDH shared secret into the protocol.
  (_, ciphertext) ← Seal(hpke, "message", plaintext)           // Seal the plaintext.
  return (ephemeral.pub, ciphertext)                           // Return the ephemeral public key and tag.
```

```text
function HPKE_Decrypt(receiver, ephemeral.pub, ciphertext):
  hpke ← Init("com.example.hpke")                              // Initialize a protocol with a domain string.
  hpke ← Mix(hpke, "receiver", receiver.pub)                   // Mix the receiver's public key into the protocol.
  hpke ← Mix(hpke, "ephemeral", ephemeral.pub)                 // Mix the ephemeral public key into the protocol.
  hpke ← Mix(hpke, "ecdh", ECDH(receiver.priv, ephemeral.pub)) // Mix the ephemeral ECDH shared secret into the protocol.
  (_, plaintext) ← Open(hpke, "message", ciphertext)           // Open the ciphertext.
  return plaintext
```

**N.B.:** This construction does not provide authentication in the public key setting. An adversary
in possession of the receiver's public key (i.e. anyone) can create ciphertexts which will decrypt
as valid. In the symmetric key setting (i.e. an adversary without the receiver's public key), this
is IND-CCA secure, but the real-world scenarios in which that applies are minimal. As-is, the tag
is more like a checksum than a MAC, preventing modifications only by adversaries who don't have the
recipient's public key.

Using a static ECDH shared secret (i.e. `ECDH(receiver.pub, sender.priv)`) would add implicit
authentication but would require a nonce or an ephemeral key to be IND-CCA secure. The resulting
scheme would be outsider secure in the public key setting (i.e. an adversary in possession of
everyone's public keys would be unable to forge or decrypt ciphertexts) but not insider secure (i.e.
an adversary in possession of the receiver's private key could forge ciphertexts from arbitrary
senders, a.k.a. key compromise impersonation).

### Digital Signatures

Lockstitch can be used to implement EdDSA-style Schnorr digital signatures:

```text
function Sign(signer, message):
  schnorr ← Init("com.example.eddsa")                     // Initialize a protocol with a domain string.
  schnorr ← Mix(schnorr, "signer", signer.pub)            // Mix the signer's public key into the protocol.
  schnorr ← Mix(schnorr, "message", message)              // Mix the message into the protocol.
  (k, I) ← P256::KeyGen()                                 // Generate a commitment scalar and point.
  schnorr ← Mix(schnorr, "commitment", I)                 // Mix the commitment point into the protocol.
  (_, r) ← P256::Scalar(Derive(schnorr, "challenge", 32)) // Derive a challenge scalar.
  s ← signer.priv * r + k                                 // Calculate the proof scalar.
  return (I, s)                                           // Return the commitment point and proof scalar.
```

The resulting signature is strongly bound to both the message and the signer's public key, making it
sUF-CMA secure. If a non-prime order group like Edwards25519 is used instead of NIST P-256, the
verification function must account for co-factors to be strongly unforgeable.

```text
function Verify(signer.pub, message, I, s):
  schnorr ← Init("com.example.eddsa")                      // Initialize a protocol with a domain string.
  schnorr ← Mix(schnorr, "signer", signer.pub)             // Mix the signer's public key into the protocol.
  schnorr ← Mix(schnorr, "message", message)               // Mix the message into the protocol.
  schnorr ← Mix(schnorr, "commitment", I)                  // Mix the commitment point into the protocol.
  (_, r′) ← P256::Scalar(Derive(schnorr, "challenge", 32)) // Derive a counterfactual challenge scalar.
  I′ ← [s]G - [r′]signer.pub                               // Calculate the counterfactual commitment point.
  return I = I′                                            // The signature is valid if both points are equal.
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
  ephemeral ← P256::KeyGen()                                  // Generate an ephemeral key pair.
  sc ← Init("com.example.sc")                                 // Initialize a protocol with a domain string.
  sc ← Mix(state, "receiver", receiver.pub)                   // Mix the receiver's public key into the protocol.
  sc ← Mix(state, "sender", sender.pub)                       // Mix the sender's public key into the protocol.
  sc ← Mix(state, "ephemeral", ephemeral.pub)                 // Mix the ephemeral public key into the protocol.
  sc ← Mix(state, "ecdh", ECDH(receiver.pub, ephemeral.priv)) // Mix the ECDH shared secret into the protocol.
  (sc, ciphertext) ← Encrypt(state, "message", plaintext)     // Encrypt the plaintext.
  (k, I) ← P256::KeyGen()                                     // Generate a commitment scalar and point.
  sc ← Mix(state, "commitment", I)                            // Mix the commitment point into the protocol.
  (_, r) ← P256::Scalar(Derive(state, "challenge", 32))       // Derive a challenge scalar.
  s ← sender.priv * r + k                                     // Calculate the proof scalar.
  return (ephemeral.pub, ciphertext, I, s)                    // Return the ephemeral public key, ciphertext, and signature.
```

```text
function Unsigncrypt(receiver, sender.pub, ephemeral.pub, I, s):
  sc ← Init("com.example.sc")                                 // Initialize a protocol with a domain string.
  sc ← Mix(state, "receiver", receiver.pub)                   // Mix the receiver's public key into the protocol.
  sc ← Mix(state, "sender", sender.pub)                       // Mix the sender's public key into the protocol.
  sc ← Mix(state, "ephemeral", ephemeral.pub)                 // Mix the ephemeral public key into the protocol.
  sc ← Mix(state, "ecdh", ECDH(receiver.priv, ephemeral.pub)) // Mix the ECDH shared secret into the protocol.
  (sc, plaintext) ← Decrypt(sc, "message", ciphertext)        // Decrypt the ciphertext.
  sc ← Mix(sc, "commitment", I)                               // Mix the commitment point into the protocol.
  (_, r′) ← P256::Scalar(Derive(sc, "challenge", 32))         // Derive a counterfactual challenge scalar.
  I′ ← [s]G - [r′]sender.pub                                  // Calculate the counterfactual commitment point.
  if I = I′:
    return plaintext                                          // If both points are equal, return the plaintext.
  else:
    return ⊥                                                  // Otherwise, return an error.
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
  eddsa ← Init("com.example.eddsa")                     // Initialize a protocol with a domain string.
  eddsa ← Mix(eddsa, "signer", signer.pub)              // Mix the signer's public key into the protocol.
  eddsa ← Mix(eddsa, "message", message)                // Mix the message into the protocol.
  with clone ← Clone(eddsa) do                          // Clone the protocol.
    clone ← Mix(clone, "signer", signer.priv)           // Mix the signer's private key into the clone.
    clone ← Mix(clone, "rand", Rand(64))                // Mix 64 random bytes into the clone.
    k ← P256::Scalar(Derive(clone, "commitment", 32))   // Derive a commitment scalar from the clone.
    I ← [k]G                                            // Calculate the commitment point.
    yield (k, I)                                        // Return the ephemeral key pair to the signing scope.
  end                                                   // Discard the cloned protocol.
  eddsa ← Mix(eddsa, "commitment", I)                   // Mix the commitment point into the protocol.
  (_, r) ← P256::Scalar(Derive(eddsa, "challenge", 32)) // Derive a challenge scalar.
  s ← signer.priv * r + k                               // Calculate the proof scalar.
  return (I, s)                                         // Return the commitment point and proof scalar.
```

[NIST SP 800-185]: https://www.nist.gov/publications/sha-3-derived-functions-cshake-kmac-tuplehash-and-parallelhash
