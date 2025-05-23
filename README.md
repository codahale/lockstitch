# Lockstitch

Lockstitch is an incremental, stateful cryptographic primitive for symmetric-key cryptographic
operations (e.g. hashing, encryption, message authentication codes, and authenticated encryption) in
complex protocols. Inspired by TupleHash, STROBE, Noise Protocol's stateful objects, Merlin
transcripts, and Xoodyak's Cyclist mode, Lockstitch uses [SHA-256][] and [AES-128][] to provide
10+ Gb/sec performance on modern processors at a 128-bit security level.

[SHA-256]: https://doi.org/10.6028/NIST.FIPS.180-4
[AES-128]: https://doi.org/10.6028/NIST.FIPS.197-upd1

## CAUTION

⚠️ You should not use this. ⚠️

Neither the design nor the implementation of this library have been independently evaluated. The
design is documented in [`design.md`](design.md); read it and see if the arguments therein are
convincing.

In addition, there is absolutely no guarantee of backwards compatibility.

## Design

A Lockstitch protocol is a stateful object which has five different operations:

* `Init`: Initializes a protocol with a domain separation string.
* `Mix`: Mixes a piece of data into the protocol's state, making all future outputs dependent on it.
* `Derive`: Outputs bytes of pseudo-random data dependent on the protocol's state.
* `Encrypt`/`Decrypt`: Encrypts and decrypts data using the protocol's state as the key.
* `Seal`/`Open`: Encrypts and decrypts data with authentication using the protocol's state as the
  key.

Using these operations, one can construct a wide variety of symmetric-key constructions.

## Use

Lockstitch is used to compose cryptographic protocols.

For example, we can create message digests:

```rust
fn digest(message: &[u8]) -> [u8; 32] {
  let mut md = lockstitch::Protocol::new("com.example.md");
  md.mix("message", message);
  md.derive_array("digest")
}

assert_eq!(digest(b"this is a message"), digest(b"this is a message"));
assert_ne!(digest(b"this is a message"), digest(b"this is another message"));
```

We can create message authentication codes:

```rust
fn mac(key: &[u8], message: &[u8]) -> [u8; 16] {
  let mut mac = lockstitch::Protocol::new("com.example.mac");
  mac.mix("key", key);
  mac.mix("message", message);
  mac.derive_array("tag")
}

assert_eq!(mac(b"a key", b"a message"), mac(b"a key", b"a message"));
assert_ne!(mac(b"a key", b"a message"), mac(b"another key", b"a message"));
assert_ne!(mac(b"a key", b"a message"), mac(b"a key", b"another message"));
```

We can even create authenticated encryption:

```rust
fn aead_encrypt(key: &[u8], nonce: &[u8], ad: &[u8], plaintext: &[u8]) -> Vec<u8> {
  let mut out = vec![0u8; plaintext.len() + lockstitch::TAG_LEN];
  out[..plaintext.len()].copy_from_slice(plaintext);

  let mut aead = lockstitch::Protocol::new("com.example.aead");
  aead.mix("key", key);
  aead.mix("nonce", nonce);
  aead.mix("ad", ad);
  aead.seal("message", &mut out);

  out
}

fn aead_decrypt(key: &[u8], nonce: &[u8], ad: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
  let mut ciphertext = ciphertext.to_vec();

  let mut aead = lockstitch::Protocol::new("com.example.aead");
  aead.mix("key", key);
  aead.mix("nonce", nonce);
  aead.mix("ad", ad);
  aead.open("message", &mut ciphertext).map(|p| p.to_vec())
}

let plaintext = b"a message".to_vec();
let ciphertext = aead_encrypt(b"a key", b"a nonce", b"some data", &plaintext);
assert_eq!(aead_decrypt(b"a key", b"a nonce", b"some data", &ciphertext), Some(plaintext));
assert_eq!(aead_decrypt(b"another key", b"a nonce", b"some data", &ciphertext), None);
assert_eq!(aead_decrypt(b"a key", b"another nonce", b"some data", &ciphertext), None);
assert_eq!(aead_decrypt(b"a key", b"a nonce", b"some other data", &ciphertext), None);

let mut bad_ciphertext = ciphertext.to_vec();
bad_ciphertext[5] ^= 1; // flip one bit
assert_eq!(aead_decrypt(b"a key", b"a nonce", b"some data", &bad_ciphertext), None);
```

## Cargo Features

* `docs`: Enables the docs-only `perf` and `design` modules.
* `std`: Enables features based on the Rust standard library. Enabled by default.

## Additional Information

For more information on the design of Lockstitch, see [`design.md`](design.md).
For more information on performance, see [`perf.md`](perf.md).

## License

Copyright © 2025 Coda Hale

Distributed under the Apache License 2.0 or MIT License.
