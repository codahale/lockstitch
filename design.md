# The Design Of Lockstitch

Lockstitch is an incremental, stateful cryptographic primitive for symmetric-key cryptographic
operations (e.g. hashing, encryption, message authentication codes, and authenticated encryption) in
complex protocols. Inspired by TupleHash, STROBE, Noise Protocol's stateful objects, Merlin
transcripts, and Xoodyak's Cyclist mode, Lockstitch uses [TurboSHAKE128][], an eXtendable Output
Function (XOF), and [AEGIS-128L][], an authenticated cipher, to provide 100+ Gb/sec performance on
modern processors at a 128-bit security level.

[TurboSHAKE128]: https://www.ietf.org/archive/id/draft-irtf-cfrg-kangarootwelve-12.html
[AEGIS-128L]: https://www.ietf.org/archive/id/draft-irtf-cfrg-aegis-aead-09.html

## Protocol

The basic unit of Lockstitch is the protocol, which encapsulates a transcript of encoded operations.

A Lockstitch protocol supports the following operations:

* `Init`: Initialize a protocol with a domain separation string.
* `Mix`: Add a labeled input to the protocol's transcript, making all future outputs
  cryptographically dependent on it.
* `Derive`: Ratchet the protocol's transcript, preventing rollback, and generate a pseudo-random
  bitstring of arbitrary length that is cryptographically dependent on the protocol's prior
  transcript.
* `Encrypt`/`Decrypt`: Encrypt and decrypt a message, adding an authenticator tag of the ciphertext
  to the protocol transcript.
* `Seal`/`Open`: Encrypt and decrypt a message, using an authenticator tag to ensure the ciphertext
  has not been modified.

Labels are used for all Lockstitch operations (except `Init`) to provide domain separation of inputs
and outputs. This ensures that semantically distinct values with identical encodings (e.g. public
keys or ECDH shared secrets) result in distinctly encoded operations so long as the labels are
distinct. Labels should be human-readable values which communicate the source of the input or the
intended use of the output. `server-p256-public-key` is a good label; `step-3a` is a bad label.

### `Init`

An `Init` operation initializes a Lockstitch protocol with a domain separation string by beginning a
transcript with a constant operation code and then performing a `Mix` operation with the domain:

```text
function init(domain):
  transcript ← 0x01                                         // Begin the transcript with an Init op code.
  transcript ← transcript ǁ domain ǁ right_encode(|domain|) // Append the encoded domain.
  transcript
```

**IMPORTANT:** The `Init` operation is only performed once, when a protocol is initialized.

`Init` encodes the length of the domain in bits using [NIST SP 800-185][]'s `right_encode`. This
ensures an unambiguous encoding for any combination of domain and second operation in the
transcript.

[NIST SP 800-185]: https://www.nist.gov/publications/sha-3-derived-functions-cshake-kmac-tuplehash-and-parallelhash

The BLAKE3 recommendations for KDF context strings apply equally to Lockstitch protocol domains:

> The context string should be hardcoded, globally unique, and application-specific. … The context
> string should not contain variable data, like salts, IDs, or the current time. (If needed, those
> can be part of the key material, or mixed with the derived key afterwards.) … The purpose of this
> requirement is to ensure that there is no way for an attacker in any scenario to cause two
> different applications or components to inadvertently use the same context string. The safest way
> to guarantee this is to prevent the context string from including input of any kind.

### `Mix`

A `Mix` operation accepts a label and an input, encodes them, and appends them to the protocol's
transcript along with a constant operation code:

```text
function mix(transcript, label, input):
  transcript ← transcript ǁ 0x02                          // Append a Mix op code to the transcript.
  transcript ← transcript ǁ label ǁ right_encode(|label|) // Append the encoded label.
  transcript ← transcript ǁ input ǁ right_encode(|input|) // Append the encoded input.
  transcript
```

`Mix` encodes the length of the label in bits and the length of the input in bits using the
`right_encode` function from [NIST SP 800-185][]. This ensures an unambiguous encoding for any
combination of label and input, regardless of length. The use of `right_encode` the length of the
input supports incremental processing of data streams whose sizes are not known in advance.

### `Derive`

A `Derive` operation accepts a label and an output length, appends them to the protocol's transcript
along with a constant operation code, hashes the transcript, replaces the transcript with derived
output, and returns the requested length of output derived from the protocol state.

```text
function derive(transcript, label, n):
  transcript ← transcript ǁ 0x03                           // Append a Derive op code to the transcript.
  transcript ← transcript ǁ label ǁ right_encode(|label|)  // Append the encoded label.
  transcript ← mix(transcript, "len", right_encode(n))     // Append a Mix operation with the output length.
  kdk ǁ output ← turboshake128(0x22, transcript, 256+n)    // Use TurboSHAKE128 to derive a KDK and the output.
  transcript ← mix(ɛ, "kdk", kdk)                          // Replace the transcript with a single Mix operation with the KDK.
  (transcript, output)                                     // Return the new transcript along with the output.
```

`Derive` appends an operation code, the operation label, and a `Mix` operation containing the
requested output length to the transcript. It then uses the transcript as input to TurboSHAKE128.
The first 256 bits of XOF output are used as a key derivation key (KDK) and the remainder is used to
generate the requested output. Finally, the transcript is replaced with a single `Mix` operation
containing the KDK.

**IMPORTANT:** A `Derive` operation's output depends on both the label and the output length.

#### KDF Security

Per the [TurboSHAKE128][] draft specification, TurboSHAKE128 offers KDF security:

> [TurboSHAKE128] can naturally be used as a key derivation function. The input must be an injective
> encoding of secret and diversification material, and the output can be taken as the derived
> key(s). The input does not need to be uniformly distributed, e.g., it can be a shared secret
> produced by the Diffie-Hellman or ECDH protocol, but it needs to have sufficient min-entropy.

The use of `right_encode` to encode all variable-length inputs is a securely injective encoding.

#### KDF Chains

Given that `Derive` is KDF-secure with respect to the protocol's transcript and replaces the
protocol's transcript with derived output, sequences of Lockstitch operations which accept input and
output in a protocol form a [KDF chain][], giving Lockstitch protocols the following security
properties:

[KDF chain]: https://signal.org/docs/specifications/doubleratchet/doubleratchet.pdf

* **Resilience**: A protocol's outputs will appear random to an adversary so long as one of the
  inputs is secret, even if the other inputs to the protocol are adversary-controlled.
* **Forward Security**: A protocol's previous outputs will appear random to an adversary even if the
  protocol's transcript is disclosed at some point.
* **Break-in Recovery**: A protocol's future outputs will appear random to an adversary in
  possession of the protocol's transcript as long as one of the future inputs to the protocol is
  secret.

### `Encrypt`/`Decrypt`

`Encrypt` and `Decrypt` operations append an operation code and a label to the transcript, append a
`Mix` operation with the plaintext length to the transcript, derive an AEGIS-128L key and nonce,
encrypt or decrypt an input with AEGIS-128L, and append a `Mix` operation with the 256-bit
AEGIS-128L tag to the transcript.

```text
function encrypt(transcript, label, plaintext):
  transcript ← transcript ǁ 0x04                                      // Append a Crypt op code to the transcript.
  transcript ← transcript ǁ label ǁ right_encode(|label|)             // Append the encoded label.
  transcript ← mix(transcript, "len", right_encode(|plaintext|))      // Append a Mix operation with the plaintext length.
  (transcript, key ǁ nonce) ← derive(transcript, "key", 256)          // Derive an AEGIS-128L key and nonce.
  (ciphertext, _, tag256) ← aegis128l::encrypt(key, nonce, plaintext) // Encrypt the plaintext.
  transcript ← mix(transcript, "tag", tag256)                         // Append a Mix operation with the 256-bit tag.
  (transcript, ciphertext)

function decrypt(transcript, label, ciphertext):
  transcript ← transcript ǁ 0x04                                      // Append a Crypt op code to the transcript.
  transcript ← transcript ǁ label ǁ right_encode(|label|)             // Append the encoded label.
  transcript ← mix(transcript, "len", right_encode(|plaintext|))      // Append a Mix operation with the plaintext length.
  (transcript, key ǁ nonce) ← derive(transcript, "key", 256)          // Derive an AEGIS-128L key and nonce.
  (plaintext, _, tag256) ← aegis128l::decrypt(key, nonce, ciphertext) // Decrypt the ciphertext.
  transcript ← mix(transcript, "tag", tag256)                         // Append a Mix operation with the 256-bit tag.
  (transcript, plaintext)
```

Three points bear mentioning about `Encrypt` and `Decrypt`:

1. Both `Encrypt` and `Decrypt` use the same operation code to ensure protocols have the same
   transcript after both encrypting and decrypting data.
2. Despite not updating the protocol transcript with either the plaintext or ciphertext, the
   inclusion of the 256-bit tag ensures the protocol's transcript is dependent on both because
   AEGIS-128L is key committing (i.e. the probability of an attacker finding a different key, nonce,
   or plaintext which produces the same authentication tag is negligible).

   **IMPORTANT:** [AEGIS-128L by itself is not fully committing][Iso23], as tag collisions can be
   found if authenticated data is attacker-controlled. Lockstitch does not pass authenticated data
   to AEGIS-128L, however, mooting this type of attack.
3. `Encrypt` operations provide no authentication by themselves. An attacker can modify a
   ciphertext and the `Decrypt` operation will return a plaintext which was never encrypted. Alone,
   they are EAV secure (i.e. a passive adversary will not be able to read plaintext without knowing
   the protocol's prior transcript) but not IND-CPA secure (i.e. an active adversary with an
   encryption oracle will be able to detect duplicate plaintexts) or IND-CCA secure (i.e. an active
   adversary can produce modified ciphertexts which successfully decrypt).

   For IND-CPA security, the protocol's transcript must include a probabilistic value (like a nonce)
   and for IND-CCA security, use [`Seal`/`Open`](#sealopen).

[Iso23]: <https://eprint.iacr.org/2023/1495>

### `Seal`/`Open`

`Seal` and `Open` operations append an operation code and a label to the transcript, append a `Mix`
operation with the plaintext length to the transcript, derive an AEGIS-128L key and nonce, encrypt
or decrypt an input with AEGIS-128L, append a `Mix` operation with the 256-bit AEGIS-128L tag to the
transcript, and append the 128-bit AEGIS-128L tag to the ciphertext.

```text
function seal(transcript, label, plaintext):
  transcript ← transcript ǁ 0x05                                           // Append an AuthCrypt op code to the transcript.
  transcript ← transcript ǁ label ǁ right_encode(|label|)                  // Append the encoded label.
  transcript ← mix(transcript, "len", right_encode(|plaintext|))           // Append a Mix operation with the plaintext length.
  (transcript, key ǁ nonce) ← derive(transcript, "key", 256)               // Derive an AEGIS-128L key and nonce.
  (ciphertext, tag128, tag256) ← aegis128l::encrypt(key, nonce, plaintext) // Encrypt the plaintext.
  transcript ← mix(transcript, "tag", tag256)                              // Append a Mix operation with the 256-bit tag.
  (transcript, ciphertext, tag128)                                         // Return the ciphertext and the 128-bit tag.

function open(transcript, label, ciphertext, tag128):
  transcript ← transcript ǁ 0x05                                           // Append an AuthCrypt op code to the transcript.
  transcript ← transcript ǁ label ǁ right_encode(|label|)                  // Append the encoded label.
  transcript ← mix(transcript, "len", right_encode(|ciphertext|-128))      // Append a Mix operation with the plaintext length.
  (transcript, key ǁ nonce) ← derive(transcript, "key", 256)               // Derive an AEGIS-128L key and nonce.
  (plaintext, tag128, tag256) ← aegis128l::decrypt(key, nonce, ciphertext) // Decrypt the ciphertext.
  transcript ← mix(transcript, "tag", tag256)                              // Append a Mix operation with the 256-bit tag.
  if tag128 = tag128′:                                                     // Compare the 128-bit tags in constant time.
    (transcript, plaintext)
  else:
    (transcript, ⊥)
```

`Seal` and `Open` provide IND-CCA2 security as long as the protocol's transcript includes a
probabilistic value, like a nonce.

## Basic Protocols

By combining operations, we can use Lockstitch to construct a wide variety of cryptographic schemes
using a single protocol.

### Message Digests

Calculating a message digest is as simple as a `Mix` and a `Derive`:

```text
function message_digest(message):
  md ← init("com.example.md")             // Initialize a protocol with a domain string.
  md ← mix(md, "message", data)           // Mix the message into the protocol.
  (_, digest) ← derive(md, "digest", 256) // Derive 256 bits of output and return it.
  digest
```

This construction is indistinguishable from a random oracle if TurboSHAKE128 is indistinguishable
from a random oracle.

### Message Authentication Codes

Adding a key to the previous construction makes it a MAC:

```text
function mac(key, message):
  mac ← init("com.example.mac")      // Initialize a protocol with a domain string.
  mac ← mix(mac, "key", key)         // Mix the key into the protocol.
  mac ← mix(mac, "message", message) // Mix the message into the protocol.
  (_, tag) ← derive(mac, "tag", 128) // Derive 128 bits of output and return it.
  tag
```

The use of labels and the encoding of [`Mix` inputs](#mix) ensures that the key and the message will
never overlap, even if their lengths vary.

### Stream Ciphers

Lockstitch can be used to create a stream cipher:

```text
function stream_encrypt(key, nonce, plaintext):
  stream ← init("com.example.stream")                         // Initialize a protocol with a domain string.
  stream ← mix(stream, "key", key)                            // Mix the key into the protocol.
  stream ← mix(stream, "nonce", nonce)                        // Mix the nonce into the protocol.
  (_, ciphertext) ← encrypt(stream, "message", plaintext)     // Encrypt the plaintext.
  ciphertext

function stream_decrypt(key, nonce, ciphertext):
  stream ← init("com.example.stream")                         // Initialize a protocol with a domain string.
  stream ← mix(stream, "key", key)                            // Mix the key into the protocol.
  stream ← mix(stream, "nonce", nonce)                        // Mix the nonce into the protocol.
  (_, plaintext) ← decrypt(stream, "message", ciphertext)     // Decrypt the ciphertext.
  plaintext 
```

This construction is IND-CPA-secure under the following assumptions:

1. AEGIS-128L is IND-CPA-secure when used with a unique nonce.
2. TurboSHAKE128 is indistinguishable from a random oracle.
3. TurboSHAKE128's XOF is PRF-secure.
4. At least one of the inputs to the transcript is a nonce (i.e., not used for multiple messages).

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
tag is a strong cryptographic commitment to all the inputs. AEGIS-128L is key-committing and both
the key and the nonce are derived from the transcript using TurboSHAKE128.

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

This construction is IND-CCA2-secure (i.e. both IND-CPA and INT-CTXT) under the following
assumptions:

1. AEGIS-128L is IND-CPA-secure when used with a unique nonce.
2. TurboSHAKE128 is indistinguishable from a random oracle.
3. TurboSHAKE128's XOF is PRF-secure.
4. At least one of the inputs to the transcript is a nonce (i.e., not used for multiple messages).

#### Expanded Transcript

To make it clear what Lockstitch is doing behind the scenes, the Lockstitch API can be converted into
a sequence of primitive operations. For example, consider the following concrete use of the
`aead_seal` function:

```text
key ← 0x06c47a03da9a2e6cdebdcafdfd62b57d
nonce ← 0x3f4ac18bfa54206f5c6de81517618d43
plaintext ← "this is a secret"
ad ← "this is public"
(ciphertext, tag) ← aead_seal(key, nonce, ad, plaintext)
```

That expands to the following sequence of primitive operations:

```text
t0 ← 0x01 || 0x01, 0x80 || "com.example.aead"
t1 ← t0 || 0x02 || "key" || 0x03, 0x01 || 0x06c47a03da9a2e6cdebdcafdfd62b57d || 0x80, 0x01 
t2 ← t1 || 0x02 || "nonce" || 0x05, 0x01 || 0x3f4ac18bfa54206f5c6de81517618d43 || 0x80, 0x01 
t3 ← t2 || 0x02 || "ad" || 0x02, 0x01 || "this is public" || 0x0e, 0x01 
t4 ← t3 || 0x05 || "message" || 0x07, 0x01
t5 ← t4 || 0x03 || "key" || 0x03, 0x01
t6 ← t5 || 0x02 || "len" || 0x03, 0x01 || 0x20, 0x01 || 0x02, 0x01
kdk0 || ek0 ← turboshake128(0x22, t6, 64) 
t7 ← 0x02 || "kdk" || 0x07, 0x01 || kdk0 || 0x20, 0x01
(ciphertext, tag128, tag256) ← aegis128l::encrypt(ek0, "this is a secret")
t8 ← t7 || 0x02 || "tag" || 0x03, 0x01 || tag256 || 0x20, 0x01
(ciphertext, tag128)
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

**WARNING:** This construction does not provide authentication in the public key setting. An
adversary in possession of the receiver's public key (i.e. anyone) can create ciphertexts which will
decrypt as valid. In the symmetric key setting (i.e. an adversary without the receiver's public
key), this is IND-CCA secure, but the real-world scenarios in which that applies are minimal. As-is,
the tag is more like a checksum than a MAC, preventing modifications only by adversaries who don't
have the recipient's public key.

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
  schnorr ← init("com.example.eddsa")                      // Initialize a protocol with a domain string.
  schnorr ← mix(schnorr, "signer", signer.pub)             // Mix the signer's public key into the protocol.
  schnorr ← mix(schnorr, "message", message)               // Mix the message into the protocol.
  (k, I) ← p256::key_gen()                                 // Generate a commitment scalar and point.
  schnorr ← mix(schnorr, "commitment", I)                  // Mix the commitment point into the protocol.
  (_, r) ← p256::scalar(derive(schnorr, "challenge", 256)) // Derive a challenge scalar.
  s ← signer.priv * r + k                                  // Calculate the proof scalar.
  (I, s)                                                   // Return the commitment point and proof scalar.
```

The resulting signature is strongly bound to both the message and the signer's public key, making it
sUF-CMA secure. If a non-prime order group like Edwards25519 is used instead of NIST P-256, the
verification function must account for co-factors to be strongly unforgeable.

```text
function verify(signer.pub, message, I, s):
  schnorr ← init("com.example.eddsa")                       // Initialize a protocol with a domain string.
  schnorr ← mix(schnorr, "signer", signer.pub)              // Mix the signer's public key into the protocol.
  schnorr ← mix(schnorr, "message", message)                // Mix the message into the protocol.
  schnorr ← mix(schnorr, "commitment", I)                   // Mix the commitment point into the protocol.
  (_, r′) ← p256::scalar(derive(schnorr, "challenge", 256)) // Derive a counterfactual challenge scalar.
  I′ ← [s]G - [r′]signer.pub                                // Calculate the counterfactual commitment point.
  I = I′                                                    // The signature is valid if both points are equal.
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
  (_, r) ← p256::scalar(derive(sc, "challenge", 256))      // Derive a challenge scalar.
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
  (_, r′) ← p256::scalar(derive(sc, "challenge", 256))     // Derive a counterfactual challenge scalar.
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
