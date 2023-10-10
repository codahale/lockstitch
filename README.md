# Lockstitch

Lockstitch is an incremental, stateful cryptographic primitive for symmetric-key cryptographic
operations (e.g. hashing, encryption, message authentication codes, and authenticated encryption) in
complex protocols. Inspired by TupleHash, STROBE, Noise Protocol's stateful objects, and Xoodyak's
Cyclist mode, Lockstitch uses AES-128-CTR and SHA-256 to provide ~1 GiB/sec performance on modern
processors at a 128-bit security level.

## ⚠️ WARNING: You should not use this. ⚠️

Neither the design nor the implementation of this library have been independently evaluated. It uses
very recent cryptographic algorithms in slightly heterodox ways and may well be just an absolutely
terrible idea. The design is documented in [`design.md`](design.md); read it and see if the
arguments therein are convincing.

In addition, there is absolutely no guarantee of backwards compatibility.

## Design

A Lockstitch protocol is a stateful object which has four different operations:

* `Mix`: Mixes a piece of data into the protocol's state, making all future outputs dependent on it.
* `Derive`: Outputs bytes of pseudo-random data dependent on the protocol's prior state.
* `Encrypt`/`Decrypt`: Encrypts and decrypts data using the protocol's state as the key.
* `Ratchet`: Irreversibly modifies the protocol's state, preventing rollback.

Using these operations, one can construct a wide variety of symmetric-key constructions.

## Use

Lockstitch is used to compose cryptographic protocols.

For example, we can create message digests:

```rust
fn digest(data: &[u8]) -> [u8; 32] {
  let mut md = lockstitch::Protocol::new("com.example.md");
  md.mix(data);
  md.derive_array()
}

assert_eq!(digest(b"this is a message"), digest(b"this is a message"));
assert_ne!(digest(b"this is a message"), digest(b"this is another message"));
```

We can create message authentication codes:

```rust
fn mac(key: &[u8], data: &[u8]) -> [u8; 16] {
  let mut mac = lockstitch::Protocol::new("com.example.mac");
  mac.mix(key);
  mac.mix(data);
  mac.derive_array()
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
  aead.mix(key);
  aead.mix(nonce);
  aead.mix(ad);
  aead.seal(&mut out);

  out
}

fn aead_decrypt(key: &[u8], nonce: &[u8], ad: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
  let mut ciphertext = ciphertext.to_vec();

  let mut aead = lockstitch::Protocol::new("com.example.aead");
  aead.mix(key);
  aead.mix(nonce);
  aead.mix(ad);
  aead.open(&mut ciphertext).map(|p| p.to_vec())
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

* `asm`: Enables hand-coded assembly for SHA-256 for `x86` and `x86_64` and a vectorized
implementation for `aarch64`. Enabled by default.
* `docs`: Enables the docs-only `perf` and `design` modules.
* `hedge`: Enables hedged random value generation with `rand_core`. Enabled by default.
* `std`: Enables features based on the Rust standard library. Enabled by default.

## Performance

### `x86`/`x86_64`

Both the `aes` and `sha2` crates auto-detect CPU support at runtime and will use the most optimized
backend.

### `aarch64`

In order to enable CPU support for AES and SHA2, enable the `asm` crate feature and include
`--cfg aes_armv8` in the `RUSTFLAGS` of your application.

## Additional Information

For more information on the design of Lockstitch, see [`design.md`](design.md).
For more information on performance, see [`perf.md`](perf.md).

## License

Copyright © 2023 Coda Hale

Distributed under the Apache License 2.0 or MIT License.
