# Lockstitch

Lockstitch is an incremental, stateful cryptographic primitive for symmetric-key cryptographic
operations (e.g. hashing, encryption, message authentication codes, and authenticated encryption) in
complex protocols. Inspired by TupleHash, STROBE, Noise Protocol's stateful objects, and Xoodyak's
Cyclist mode, Lockstitch uses the [AEGIS-128L][] authenticated cipher and SHA-256 to provide 100+
Gb/sec performance on modern processors at a 128-bit security level.

[AEGIS-128L]: https://www.ietf.org/archive/id/draft-irtf-cfrg-aegis-aead-03.html

## ⚠️ WARNING: You should not use this. ⚠️

Neither the design nor the implementation of this library have been independently evaluated. It uses
very recent cryptographic algorithms in slightly heterodox ways and may well be just an absolutely
terrible idea. The design is documented in [`design.md`](design.md); read it and see if the
arguments therein are convincing.

In addition, there is absolutely no guarantee of backwards compatibility.

## Design

A Lockstitch protocol is a stateful object which has five different operations:

* `Mix`: Mixes a piece of data into the protocol's state, making all future outputs dependent on it.
* `Derive`: Outputs bytes of pseudo-random data dependent on the protocol's prior state.
* `Encrypt`/`Decrypt`: Encrypts and decrypts data using the protocol's state as the key.
* `Seal`/`Open`: Similar to `Encrypt`/`Decrypt` but uses a MAC to ensure authenticity.
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
* `hedge`: Enables hedged random value generation with `rand_core`. Enabled by default.
* `portable`: Uses the portable `aes` crate for AEGIS-128L at a steep performance penalty.
* `std`: Enables features based on the Rust standard library. Enabled by default.

## Performance

Lockstitch's SHA-256 and AEGIS-128L implementations benefit significantly from the use of specific
CPU instructions.

### `x86`/`x86_64`

On `x86`/`x86_64` CPUs, Lockstitch achieves its best performance with the `aes` and `ssse3` target
features enabled.

To compile a binary with support for these features, create a `.cargo/config.toml` file with the
following:

```toml
[build]
rustflags = ["-C", "target-feature=+aes,+ssse3"]
```

Or use the following `RUSTFLAGS` environment variable:

```sh
export RUSTFLAGS="-C target-feature=+aes,+ssse3"
```

### `aarch64`

On `aarch64-darwin-apple` (i.e. macOS), the ARMv8-A cryptography instructions and NEON vector
instructions are enabled by default. On other targets (e.g. `aarch64-unknown-linux-gnu`), the `sha3`
and `aes` target features should be enabled.

### Other

For other platforms, the `portable` crate feature provides a very slow but fully portable AES
implementation.

## Additional Information

For more information on the design of Lockstitch, see [`design.md`](design.md).
For more information on performance, see [`perf.md`](perf.md).

## License

Copyright © 2023 Coda Hale, Frank Denis

AEGIS-128L implementation adapted from [rust-aegis](https://github.com/jedisct1/rust-aegis/).

Distributed under the MIT License.
