# Lockstitch

Lockstitch is an incremental, stateful cryptographic primitive for symmetric-key cryptographic
operations (e.g. hashing, encryption, message authentication codes, and authenticated encryption) in
complex protocols. Inspired by TupleHash, STROBE, Noise Protocol's stateful objects, Merlin
transcripts, and Xoodyak's Cyclist mode, Lockstitch uses [TurboSHAKE128][], an eXtendable Output
Function (XOF), and [AEGIS-128L][], an authenticated cipher, to provide 100+ Gb/sec performance on
modern processors at a 128-bit security level.

[TurboSHAKE128]: https://www.ietf.org/archive/id/draft-irtf-cfrg-kangarootwelve-12.html
[AEGIS-128L]: https://www.ietf.org/archive/id/draft-irtf-cfrg-aegis-aead-09.html

## CAUTION

⚠️ You should not use this. ⚠️

Neither the design nor the implementation of this library have been independently evaluated. The
design is documented in [`design.md`](design.md); read it and see if the arguments therein are
convincing. CryptoVerif proofs can be found in the `proofs` directory; read them and see if the
models and games therein are accurate.

In addition, there is absolutely no guarantee of backwards compatibility.

## Design

A Lockstitch protocol is a stateful object which has five different operations:

* `Init`: Initializes a protocol with a domain separation string.
* `Mix`: Mixes a piece of data into the protocol's transcript, making all future outputs dependent
  on it.
* `Derive`: Outputs bytes of pseudo-random data dependent on the protocol's transcript.
* `Encrypt`/`Decrypt`: Encrypts and decrypts data using the protocol's transcript as the key.
* `Seal`/`Open`: Encrypts and decrypts data with authentication using the protocol's transcript as
  the key.

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

* `asm`: Enables hand-coded assembly for TurboSHAKE128 for `aarch64`. Enabled by default.
* `docs`: Enables the docs-only `perf` and `design` modules.
* `hedge`: Enables hedged random value generation with `rand_core`. Enabled by default.
* `std`: Enables features based on the Rust standard library. Enabled by default.

## Performance

Lockstitch's AEGIS-128L implementation benefit significantly from the use of specific CPU
instructions.

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
