# The Design Of Lockstitch

Lockstitch provides a single cryptographic service for all symmetric-key operations and an
incremental, stateful building block for complex schemes, constructions, and protocols, all built on
top of SHA-256 and [AEGIS-128L][], an authenticated cipher.

[AEGIS-128L]: https://www.ietf.org/archive/id/draft-irtf-cfrg-aegis-aead-06.html

## Protocol

The basic unit of Lockstitch is the protocol, which encapsulates a transcript of encoded operations.

A Lockstitch protocol supports the following operations:

* `Mix`, which adds a labeled input to the protocol's transcript.
* `Init`, which initializes a protocol with a domain separation string.
* `Ratchet`, which replaces the protocol's transcript with a hash of the transcript, preventing
  rollback.
* `Derive`, which produces a bitstring of arbitrary length that is cryptographically dependent on
  the protocol's transcript.
* `Encrypt`/`Decrypt`, which encrypt and decrypt a message, adding an authentication tag of the
  ciphertext to the protocol transcript.
* `Seal`/`Open`, which encrypt and decrypt a message, using an authenticator tag to ensure the
  ciphertext has not been modified.

Labels are used for all Lockstitch operations (except `Init` and `Ratchet`) to provide domain
separation of inputs and outputs. This ensures that semantically distinct values with identical
encodings (e.g. public keys or ECDH shared secrets) result in distinctly encoded operations so long
as the labels are distinct. Labels should be human-readable values which communicate the source of
the input or the intended use of the output. `server-p256-public-key` is a good label; `step-3a` is
a bad label.

### `Mix`

A `Mix` operation accepts a label and an input, encodes them, and appends them to the protocol's
transcript along with a constant operation code:

```text
function mix(transcript, label, input):
  transcript ← transcript ǁ 0x01                          // Append a Mix op code to the transcript.
  transcript ← transcript ǁ left_encode(|label|) ǁ label  // Append the encoded label.
  transcript ← transcript ǁ input ǁ right_encode(|input|) // Append the encoded input.
  transcript
```

`Mix` encodes the length of the label in bits and the length of the input in bits using
`left_encode` and `right_encode` from [NIST SP 800-185][], respectively. This ensures an unambiguous
encoding for any combination of label and input, regardless of length. `right_encode` is used for
the length of the input to support incremental processing of data streams whose sizes are not known
in advance.

[NIST SP 800-185]: https://www.nist.gov/publications/sha-3-derived-functions-cshake-kmac-tuplehash-and-parallelhash

**N.B.**: Processing more than 2^64 bytes of input without [ratcheting](#ratchet) will result in
undefined behavior.

### `Init`

An `Init` operation initializes a Lockstitch protocol with a domain separation string by beginning a
transcript with a constant operation code and then performing a `Mix` operation with the domain:

```text
function init(domain):
  transcript ← 0x02                                  // Begin a new transcript with an Init op code.
  transcript ← transcript ǁ mix(ɛ, "domain", domain) // Append a Mix operation with the domain.
  transcript
```

The BLAKE3 recommendations for KDF context strings apply equally to Lockstitch protocol domains:

> The context string should be hardcoded, globally unique, and application-specific. … The context
> string should not contain variable data, like salts, IDs, or the current time. (If needed, those
> can be part of the key material, or mixed with the derived key afterwards.) … The purpose of this
> requirement is to ensure that there is no way for an attacker in any scenario to cause two
> different applications or components to inadvertently use the same context string. The safest way
> to guarantee this is to prevent the context string from including input of any kind.

**N.B.:** The `Init` operation is only performed once, when a protocol is initialized.

### `Ratchet`

A `Ratchet` operation replaces the protocol's transcript with a single `Mix` operation with a
derived key of the previous transcript as input and returns additional derived output of the given
length.

```text
function ratchet(transcript, n):
  transcript ← transcript ǁ 0x03          // Append a Ratchet op code to the transcript.
  ikm ← sha256(transcript)                // Hash the transcript in its entirety.
  kdf_out ← kdf(ikm, "lockstitch", 32+n)  // Derive 32+n bytes of KDF output from the hash.
  kdf_key ǁ output ← kdf_out              // Split the KDF output into a 32-byte KDF key and returned output.
  transcript ← mix(ɛ, "kdf-key", kdf_key) // Replace the transcript with a single Mix operation with the KDF key.
  (transcript, output)                    // Return the new transcript along with the output.
```

`Ratchet` appends an operation code to the protocol's transcript, hashes the entire transcript with
SHA-256 and passes the result to the _One-Step Key Derivation_ key derivation function (KDF) from
Sec. 4 of [NIST SP 800-56C Rev. 2][] (also known as Concat-KDF), using SHA-256 as the `H` function
and the string `lockstitch` as the `FixedInfo` parameter.  Finally, the transcript is replaced with
a single `Mix` operation containing the first 32 bytes of KDF output and the remainder is returned.

[NIST SP 800-56C Rev. 2]: https://csrc.nist.gov/pubs/sp/800/56/c/r2/final

#### KDF Chains

Given that `Ratchet` is KDF-secure with respect to the protocol's transcript and replaces the
protocol's transcript with derived output, sequences of Lockstitch operations which accept input and
output in a protocol therefore constitute a [KDF chain][], giving Lockstitch protocols the following
security properties:

[KDF chain]: https://signal.org/docs/specifications/doubleratchet/doubleratchet.pdf

* **Resilience**: A protocol's outputs will appear random to an adversary so long as one of the
  inputs is secret, even if the other inputs to the protocol are adversary-controlled.
* **Forward Security**: A protocol's previous outputs will appear random to an adversary even if the
  protocol's transcript is disclosed at some point.
* **Break-in Recovery**: A protocol's future outputs will appear random to an adversary in
  possession of the protocol's transcript as long as one of the future inputs to the protocol is
  secret.

### `Derive`

A `Derive` operation appends an operation code and a label to the protocol's transcript and ratchets
the transcript, generating the given number of bits of output. Finally, it performs a `Mix`
operation with the number of bits produced as input.

```text
function derive(transcript, label, n):
  transcript ← transcript ǁ 0x04                          // Append a Derive op code to the transcript.
  transcript ← transcript ǁ left_encode(|label|) ǁ label  // Append the encoded label.
  (transcript, out) ← ratchet(transcript, n)              // Ratchet the protocol transcript and generate output.
  transcript ← mix(transcript, "len", left_encode(n))     // Append a Mix operation with the output length.
  (transcript, out)
```

A `Derive` operation's output is indistinguishable from random by an adversary who does not know the
protocol's transcript prior to the operation, assuming that SHA-256 is collision-resistant and
`Ratchet` is KDF secure. The protocol's transcript after the operation is dependent on both the fact
that the operation was a `Derive` operation as well as the number of bytes produced.

`Derive` supports streaming output, thus a shorter `Derive` operation will return a prefix of a
longer one (e.g.  `Derive("a", 16)` and `Derive("a", 32)` will share the same initial 16 bytes).
Once the operation is complete, however, the protocols' transcripts will be different. If a use case
requires `Derive` output to be dependent on its length, include the length in a `Mix` operation
beforehand.

**N.B.**: Each operation is limited to 2^40-32 bytes of output.

### `Encrypt`/`Decrypt`

`Encrypt` and `Decrypt` operations append an operation code and a label to the transcript, ratchet
the protocol's transcript to generate an AEGIS-128L key and nonce, encrypt or decrypt an input with
AEGIS-128L, and include the AEGIS-128L tag via a `Mix` operation.

```text
function encrypt(transcript, label, plaintext):
  transcript ← transcript ǁ 0x05                                // Append a Crypt op code to the transcript.
  transcript ← transcript ǁ left_encode(|label|) ǁ label        // Append the encoded label.
  (transcript, key ǁ nonce) ← ratchet(transcript, 32)           // Ratchet the protocol transcript.
  (ciphertext, tag) ← aegis128l::encrypt(key, nonce, plaintext) // Encrypt the plaintext.
  transcript ← mix(transcript, "tag", tag)                      // Append a Mix operation with the tag.
  (transcript, ciphertext)

function decrypt(transcript, label, ciphertext):
  transcript ← transcript ǁ 0x05                                // Append a Crypt op code to the transcript.
  transcript ← transcript ǁ left_encode(|label|) ǁ label        // Append the encoded label.
  (transcript, key ǁ nonce) ← ratchet(transcript, 32)           // Ratchet the protocol transcript.
  (plaintext, tag) ← aegis128l::decrypt(key, nonce, ciphertext) // Decrypt the ciphertext.
  transcript ← mix(transcript, "tag", tag)                      // Append a Mix operation with the tag.
  (transcript, plaintext)
```

Three points bear mentioning about `Encrypt` and `Decrypt`.

First, both `Encrypt` and `Decrypt` use the same operation code to ensure protocols have the same
transcript after both encrypting and decrypting data.

Second, despite not updating the protocol transcript with either the plaintext or ciphertext, the
inclusion of the long tag ensures the protocol's transcript is dependent on both because AEGIS-128L
is key committing (i.e. the probability of an attacker finding a different key, nonce, or plaintext
which produces the same authentication tag is negligible).

**N.B.:** [AEGIS-128L by itself is not fully committing][Iso23], as tag collisions can be found if
authenticated data is attacker-controlled. Lockstitch does not pass authenticated data to
AEGIS-128L, however, mooting this type of attack.

[Iso23]: https://eprint.iacr.org/2023/1495

Third, `Encrypt` operations provide no authentication by themselves. An attacker can modify a
ciphertext and the `Decrypt` operation will return a plaintext which was never encrypted. Alone,
they are EAV secure (i.e. a passive adversary will not be able to read plaintext without knowing the
protocol's prior transcript) but not IND-CPA secure (i.e. an active adversary with an encryption
oracle will be able to detect duplicate plaintexts) or IND-CCA secure (i.e. an active adversary can
produce modified ciphertexts which successfully decrypt). For IND-CPA and IND-CCA security, use
[`Seal`/`Open`](#sealopen).

As with `Derive`, `Encrypt`'s streaming support means an `Encrypt` operation with a shorter
plaintext produces a keystream which is a prefix of one with a longer plaintext (e.g.  `Encrypt("0",
"alpha")` and `Encrypt("0", "alphabet")` will produce ciphertexts with the same initial 5 bytes).
Once the operation is complete, however, the protocols' transcript would be different. If a use case
requires ciphertexts to be dependent on their length, include the length in a `Mix` operation
beforehand.

### `Seal`/`Open`

`Seal` and `Open` operations combine an `Encrypt` operation with a `Derive` operation to provide
authenticated encryption, returning a ciphertext and an authentication tag.

```text
function seal(transcript, label, plaintext):
  transcript ← transcript ǁ 0x06                                       // Append an AuthCrypt op code to the transcript.
  transcript ← transcript ǁ left_encode(|label|) ǁ label               // Append the encoded label.
  (transcript, ciphertext) ← encrypt(transcript, "message", plaintext) // Encrypt the plaintext.
  (transcript, tag) ← derive(transcript, "tag", 16)                    // Derive an authentication tag.
  (transcript, ciphertext, tag)

function open(transcript, label, ciphertext, tag):
  transcript ← transcript ǁ 0x06                                       // Append an AuthCrypt op code to the transcript.
  transcript ← transcript ǁ left_encode(|label|) ǁ label               // Append the encoded label.
  (transcript, plaintext) ← decrypt("message", ciphertext)             // Decrypt the ciphertext.
  (transcript, tag′) ← derive(transcript, "tag", 16)                   // Derive a counterfactual authentication tag.
  if tag = tag′:                                                       // Compare the tags in constant time.
    (transcript, plaintext)
  else:
    (transcript, ⊥)
```

## Basic Protocols

By combining operations, we can use Lockstitch to construct a wide variety of cryptographic schemes
using a single protocol.

### Message Digests

Calculating a message digest is as simple as a `Mix` and a `Derive`:

```text
function message_digest(message):
  md ← init("com.example.md")            // Initialize a protocol with a domain string.
  md ← mix(md, "message", data)          // Mix the message into the protocol.
  (_, digest) ← derive(md, "digest", 32) // Derive 32 bytes of output and return it.
  digest
```

This construction is collision-resistant if SHA-256 is collision-resistant.

### Message Authentication Codes

Adding a key to the previous construction makes it a MAC:

```text
function mac(key, message):
  mac ← init("com.example.mac")      // Initialize a protocol with a domain string.
  mac ← mix(mac, "key", key)         // Mix the key into the protocol.
  mac ← mix(mac, "message", message) // Mix the message into the protocol.
  (_, tag) ← derive(mac, "tag", 16)  // Derive 16 bytes of output and return it.
  tag
```

The use of labels and the encoding of [`Mix` inputs](#mix) ensures that the key and the message will
never overlap, even if their lengths vary.

### Authenticated Encryption And Data (AEAD)

Lockstitch can be used to create an AEAD:

```text
function aead_seal(key, nonce, ad, plaintext):
  aead ← init("com.example.aead")                         // Initialize a protocol with a domain string.
  aead ← mix(aead, "key", key)                            // Mix the key into the protocol.
  aead ← mix(aead, "nonce", nonce)                        // Mix the nonce into the protocol.
  aead ← mix(aead, "ad", ad)                              // Mix the associated data into the protocol.
  (_, ciphertext, tag) ← seal(aead, "message", plaintext) // Seal the plaintext.
  (ciphertext, tag)
```

The introduction of a nonce makes the scheme probabilistic (which is required for IND-CCA security).

Unlike many standard AEADs (e.g. AES-GCM and ChaCha20Poly1305), it is fully context-committing: the
tag is a strong cryptographic commitment to all the inputs. Similar to the [CTX construction][CTX],
which replaces the tag of an existing AEAD with `H(K, N, A, T)`, the final `Seal` operation closes
over all inputs--key, nonce, associated data, and plaintext--which are also the values used to
produce the ciphertext. Finding a pair of `(key, nonce, ad, plaintext)` tuples which produce the
same tag would similarly imply a lack of UF-CMA security for AEGIS-128L or collision resistance for
SHA-256.

[CTX]: https://par.nsf.gov/servlets/purl/10391723

Also unlike a standard AEAD, this can be easily extended to allow for multiple, independent pieces
of associated data without risk of ambiguous inputs.

```text
function aead_open(key, nonce, ad, ciphertext, tag):
  aead ← init("com.example.aead")                         // Initialize a protocol with a domain string.
  aead ← mix(aead, "key", key)                            // Mix the key into the protocol.
  aead ← mix(aead, "nonce", nonce)                        // Mix the nonce into the protocol.
  aead ← mix(aead, "ad", ad)                              // Mix the associated data into the protocol.
  (_, plaintext) ← open(aead, "message", ciphertext, tag) // Open the ciphertext.
  plaintext                                               // Return the plaintext or an error.
```

## Complex Protocols

Given an elliptic curve group like NIST P-256, Lockstitch can be used to build complex protocols
which integrate public- and symmetric-key operations.

### Hybrid Public-Key Encryption

Lockstitch can be used to build an integrated [ECIES][]-style public key encryption
scheme:

[ECIES]: https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme

```text
function hpke_encrypt(receiver.pub, plaintext):
  ephemeral ← p256::key_gen()                                  // Generate an ephemeral key pair.
  hpke ← init("com.example.hpke")                              // Initialize a protocol with a domain string.
  hpke ← mix(hpke, "receiver", receiver.pub)                   // Mix the receiver's public key into the protocol.
  hpke ← mix(hpke, "ephemeral", ephemeral.pub)                 // Mix the ephemeral public key into the protocol.
  hpke ← mix(hpke, "ecdh", ecdh(receiver.pub, ephemeral.priv)) // Mix the ephemeral ECDH shared secret into the protocol.
  (_, ciphertext, tag) ← seal(hpke, "message", plaintext)      // Seal the plaintext.
  (ephemeral.pub, ciphertext, tag)                             // Return the ephemeral public key and tag.
```

```text
function hpke_decrypt(receiver, ephemeral.pub, ciphertext, tag):
  hpke ← init("com.example.hpke")                              // Initialize a protocol with a domain string.
  hpke ← mix(hpke, "receiver", receiver.pub)                   // Mix the receiver's public key into the protocol.
  hpke ← mix(hpke, "ephemeral", ephemeral.pub)                 // Mix the ephemeral public key into the protocol.
  hpke ← mix(hpke, "ecdh", ecdh(receiver.priv, ephemeral.pub)) // Mix the ephemeral ECDH shared secret into the protocol.
  (_, plaintext) ← open(hpke, "message", ciphertext, tag)      // Open the ciphertext.
  plaintext
```

**N.B.:** This construction does not provide authentication in the public key setting. An adversary
in possession of the receiver's public key (i.e. anyone) can create ciphertexts which will decrypt
as valid. In the symmetric key setting (i.e. an adversary without the receiver's public key), this
is IND-CCA secure, but the real-world scenarios in which that applies are minimal. As-is, the tag
is more like a checksum than a MAC, preventing modifications only by adversaries who don't have the
recipient's public key.

Using a static ECDH shared secret (i.e. `ecdh(receiver.pub, sender.priv)`) would add implicit
authentication but would require a nonce or an ephemeral key to be IND-CCA secure. The resulting
scheme would be outsider secure in the public key setting (i.e. an adversary in possession of
everyone's public keys would be unable to forge or decrypt ciphertexts) but not insider secure (i.e.
an adversary in possession of the receiver's private key could forge ciphertexts from arbitrary
senders, a.k.a. key compromise impersonation).

### Digital Signatures

Lockstitch can be used to implement EdDSA-style Schnorr digital signatures:

```text
function sign(signer, message):
  schnorr ← init("com.example.eddsa")                     // Initialize a protocol with a domain string.
  schnorr ← mix(schnorr, "signer", signer.pub)            // Mix the signer's public key into the protocol.
  schnorr ← mix(schnorr, "message", message)              // Mix the message into the protocol.
  (k, I) ← p256::key_gen()                                // Generate a commitment scalar and point.
  schnorr ← mix(schnorr, "commitment", I)                 // Mix the commitment point into the protocol.
  (_, r) ← p256::scalar(derive(schnorr, "challenge", 32)) // Derive a challenge scalar.
  s ← signer.priv * r + k                                 // Calculate the proof scalar.
  (I, s)                                                  // Return the commitment point and proof scalar.
```

The resulting signature is strongly bound to both the message and the signer's public key, making it
sUF-CMA secure. If a non-prime order group like Edwards25519 is used instead of NIST P-256, the
verification function must account for co-factors to be strongly unforgeable.

```text
function verify(signer.pub, message, I, s):
  schnorr ← init("com.example.eddsa")                      // Initialize a protocol with a domain string.
  schnorr ← mix(schnorr, "signer", signer.pub)             // Mix the signer's public key into the protocol.
  schnorr ← mix(schnorr, "message", message)               // Mix the message into the protocol.
  schnorr ← mix(schnorr, "commitment", I)                  // Mix the commitment point into the protocol.
  (_, r′) ← p256::scalar(derive(schnorr, "challenge", 32)) // Derive a counterfactual challenge scalar.
  I′ ← [s]G - [r′]signer.pub                               // Calculate the counterfactual commitment point.
  I = I′                                                   // The signature is valid if both points are equal.
```

An additional variation on this construction uses `Encrypt` instead of `Mix` to include the
commitment point `I` in the protocol's transcript. This makes it impossible to recover the signer's
public key from a message and signature (which may be desirable for privacy in some contexts) at the
expense of making batch verification impossible.

### Signcryption

Lockstitch can be used to integrate a [HPKE](#hybrid-public-key-encryption) scheme and
a [digital signature](#digital-signatures) scheme to produce a signcryption scheme, providing both
confidentiality and strong authentication in the public key setting:

```text
function signcrypt(sender, receiver.pub, plaintext):
  ephemeral ← p256::key_gen()                              // Generate an ephemeral key pair.
  sc ← init("com.example.sc")                              // Initialize a protocol with a domain string.
  sc ← mix(sc, "receiver", receiver.pub)                   // Mix the receiver's public key into the protocol.
  sc ← mix(sc, "sender", sender.pub)                       // Mix the sender's public key into the protocol.
  sc ← mix(sc, "ephemeral", ephemeral.pub)                 // Mix the ephemeral public key into the protocol.
  sc ← mix(sc, "ecdh", ecdh(receiver.pub, ephemeral.priv)) // Mix the ECDH shared secret into the protocol.
  (sc, ciphertext) ← encrypt(sc, "message", plaintext)     // Encrypt the plaintext.
  (k, I) ← p256::key_gen()                                 // Generate a commitment scalar and point.
  sc ← mix(sc, "commitment", I)                            // Mix the commitment point into the protocol.
  (_, r) ← p256::scalar(derive(sc, "challenge", 32))       // Derive a challenge scalar.
  s ← sender.priv * r + k                                  // Calculate the proof scalar.
  (ephemeral.pub, ciphertext, I, s)                        // Return the ephemeral public key, ciphertext, and signature.
```

```text
function unsigncrypt(receiver, sender.pub, ephemeral.pub, I, s):
  sc ← init("com.example.sc")                              // Initialize a protocol with a domain string.
  sc ← mix(sc, "receiver", receiver.pub)                   // Mix the receiver's public key into the protocol.
  sc ← mix(sc, "sender", sender.pub)                       // Mix the sender's public key into the protocol.
  sc ← mix(sc, "ephemeral", ephemeral.pub)                 // Mix the ephemeral public key into the protocol.
  sc ← mix(sc, "ecdh", ecdh(receiver.priv, ephemeral.pub)) // Mix the ECDH shared secret into the protocol.
  (sc, plaintext) ← decrypt(sc, "message", ciphertext)     // Decrypt the ciphertext.
  sc ← mix(sc, "commitment", I)                            // Mix the commitment point into the protocol.
  (_, r′) ← p256::scalar(derive(sc, "challenge", 32))      // Derive a counterfactual challenge scalar.
  I′ ← [s]G - [r′]sender.pub                               // Calculate the counterfactual commitment point.
  if I = I′:
    plaintext                                              // If both points are equal, return the plaintext.
  else:
    ⊥                                                      // Otherwise, return an error.
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
inputs to the protocol. The challenge scalar `r` is derived from the protocol's transcript, which
depends on (among other things) the ECDH shared secret. Unless the adversary already knows the
shared secret (i.e. the secret key that the plaintext is encrypted with) they can't create their own
signature (which they're trying to do in order to trick someone into giving them the plaintext).

An adversary attacking an `StE` scheme can decrypt a signed message sent to them and re-encrypt it
for someone else, allowing them to pose as the original sender. This scheme makes simple replay
attacks impossible by including both the intended sender and receiver's public keys in the protocol
transcript. The initial [HPKE](#hybrid-public-key-encryption)-style portion of the protocol can be
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
function hedged_sign(signer, message):
  eddsa ← init("com.example.eddsa")                     // Initialize a protocol with a domain string.
  eddsa ← mix(eddsa, "signer", signer.pub)              // Mix the signer's public key into the protocol.
  eddsa ← mix(eddsa, "message", message)                // Mix the message into the protocol.
  with clone ← clone(eddsa) do                          // Clone the protocol.
    clone ← mix(clone, "signer", signer.priv)           // Mix the signer's private key into the clone.
    clone ← mix(clone, "rand", rand(64))                // Mix 64 random bytes into the clone.
    k ← p256::scalar(derive(clone, "commitment", 32))   // Derive a commitment scalar from the clone.
    I ← [k]G                                            // Calculate the commitment point.
    yield (k, I)                                        // Return the ephemeral key pair to the signing scope.
  end                                                   // Discard the cloned protocol.
  eddsa ← mix(eddsa, "commitment", I)                   // Mix the commitment point into the protocol.
  (_, r) ← p256::scalar(derive(eddsa, "challenge", 32)) // Derive a challenge scalar.
  s ← signer.priv * r + k                               // Calculate the proof scalar.
  (I, s)                                                // Return the commitment point and proof scalar.
```
