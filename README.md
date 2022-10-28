# Lockstitch

Lockstitch is an incremental, stateful cryptographic primitive for symmetric-key cryptographic
operations (e.g. hashing, encryption, message authentication codes, and authenticated encryption)
in complex protocols. Inspired by TupleHash, STROBE, Noise Protocol's stateful objects, and
Xoodyak's Cyclist mode, Lockstitch combines BLAKE3 and ChaCha8 to provide GiB/sec performance on
modern processors at a 128-bit security level.

## ⚠️ WARNING: You should not use this. ⚠️

Neither the design nor the implementation of this library have been independently evaluated.

## Design

A Lockstitch protocol is a stateful object which has five different operations:

* `Mix`: Mixes a piece of data into the protocol's state, making all future outputs dependent on it.
* `Derive`: Outputs bytes of pseudo-random data dependent on the protocol's prior state.
* `Encrypt`/`Decrypt`: Encrypts and decrypts data using the protocol's state as the key.
* `Tag`/`CheckTag`: Generates and verifies authenticator tags of the protocol's state.
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

## Performance

Both BLAKE3 and ChaCha8 benefit significantly from the use of SIMD operations, allowing them to
process larger inputs and outputs in parallel.

The SIMD optimizations in the `blake3` and `chacha20` crates require enabling specific CPU features
in your build. `blake3` has optimizations for AVX2, AVX512, SSE2, and SSE4.1 on Intel CPUs and NEON
on ARM CPUs. `chacha20` has optimizations for AVX2 and SSE2 on Intel CPUs.

To compile a x86-64 binary with support for AVX2 and SSE2, for example, create a
`.cargo/config.toml` file with the following:

```toml
[build]
rustflags = ["-C", "target-features=+avx2,+sse2"]
```

To compile a non-portable binary which enables all optimizations for the specific CPU on the
compiling machine, create a `.cargo/config.toml` file with the following:

```toml
[build]
rustflags = ["-C", "target-cpu=native"]
```

## Additional Information

For more information on the design of Lockstitch, see [`design.md`](design.md).
For more information on performance, see [`perf.md`](perf.md).

## License

Copyright © 2022 Coda Hale

Distributed under the Apache License 2.0 or MIT License.
