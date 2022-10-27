# Lockstitch

Lockstitch is an incremental, stateful cryptographic primitive for symmetric-key cryptographic
operations (e.g. hashing, encryption, message authentication codes, and authenticated encryption)
in complex protocols. Inspired by TupleHash, STROBE, Noise Protocol's stateful objects, and
Xoodyak's Cyclist mode, Lockstitch combines BLAKE3 and ChaCha8 to provide GiB/sec performance on
modern processors at a 128-bit security level.

## ⚠️ WARNING: You should not use this. ⚠️

Neither the design nor the implementation of this library have been independently evaluated.

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
  mac.tag_array()
}

assert_eq!(mac(b"a key", b"a message"), mac(b"a key", b"a message"));
```

We can even create authenticated encryption:

```rust
fn aead_encrypt(key: &[u8], nonce: &[u8], ad: &[u8], plaintext: &[u8]) -> Vec<u8> {
  let mut out = vec![0u8; plaintext.len() + lockstitch::TAG_LEN];
  let (ciphertext, tag) = out.split_at_mut(plaintext.len());
  ciphertext.copy_from_slice(plaintext);

  let mut aead = lockstitch::Protocol::new("com.example.aead");
  aead.mix(key);
  aead.mix(nonce);
  aead.mix(ad);
  aead.encrypt(ciphertext);
  aead.tag(tag);

  out
}

fn aead_decrypt(key: &[u8], nonce: &[u8], ad: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
  let (ciphertext, tag) = ciphertext.split_at(ciphertext.len() - lockstitch::TAG_LEN);
  let mut plaintext = ciphertext.to_vec();

  let mut aead = lockstitch::Protocol::new("com.example.aead");
  aead.mix(key);
  aead.mix(nonce);
  aead.mix(ad);
  aead.decrypt(&mut plaintext);
  aead.check_tag(tag).then_some(plaintext)
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

* `std`: Enables features based on the Rust standard library. Enabled by default.
* `hedge`: Enables hedged random value generation with `rand_core`. Enabled by default.

**N.B.:** The SIMD optimizations in `blake3` require either the use of the `std` feature or setting
`RUSTFLAGS="-C target-cpu=native"` in your build.

## Additional Information

For more information on the design of Lockstitch, see [`design.md`](design.md).
For more information on performance, see [`perf.md`](perf.md).

## License

Copyright © 2022 Coda Hale

Distributed under the Apache License 2.0 or MIT License.
