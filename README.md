# Lockstitch

Lockstitch is an incremental, stateful cryptographic primitive for symmetric-key cryptographic
operations (e.g.  hashing, encryption, message authentication codes, and authenticated encryption)
in complex protocols.  Inspired by TupleHash, STROBE, Noise Protocol's stateful objects, and
Xoodyak's Cyclist mode, Lockstitch combines BLAKE3 and ChaCha8 to provide GiB/sec performance on
modern processors at a 128-bit security level.

## Use

Lockstitch is used to compose cryptographic protocols.

For example, we can create message digests:

```rust
fn digest(data: &[u8]) -> [u8; 32] {
  let mut out = [0u8; 32];
  let mut md = lockstitch::Protocol::new("com.example.md");
  md.mix(data);
  md.derive(&mut out);
  out
}

assert_eq!(digest(b"this is a message"), digest(b"this is a message"));
assert_ne!(digest(b"this is a message"), digest(b"this is another message"));
```

We can create message authentication codes:

```rust
fn mac(key: &[u8], data: &[u8]) -> [u8; 32] {
  let mut out = [0u8; 32];
  let mut mac = lockstitch::Protocol::new("com.example.mac");
  mac.mix(key);
  mac.mix(data);
  mac.derive(&mut out);
  out
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

For more information, see [`design.md`](design.md).

## Performance

```text
hash/16B                time:   [246.66 ns 246.78 ns 246.98 ns]
                        thrpt:  [61.781 MiB/s 61.832 MiB/s 61.862 MiB/s]
hash/256B               time:   [437.25 ns 437.42 ns 437.67 ns]
                        thrpt:  [557.82 MiB/s 558.14 MiB/s 558.36 MiB/s]
hash/1KiB               time:   [1.0662 µs 1.0663 µs 1.0664 µs]
                        thrpt:  [915.72 MiB/s 915.85 MiB/s 915.96 MiB/s]
hash/16KiB              time:   [6.1419 µs 6.1430 µs 6.1442 µs]
                        thrpt:  [2.4834 GiB/s 2.4839 GiB/s 2.4844 GiB/s]
hash/1MiB               time:   [164.42 µs 164.49 µs 164.57 µs]
                        thrpt:  [5.9339 GiB/s 5.9368 GiB/s 5.9394 GiB/s]

prf/16B                 time:   [248.46 ns 248.49 ns 248.53 ns]
                        thrpt:  [61.397 MiB/s 61.405 MiB/s 61.413 MiB/s]
prf/256B                time:   [359.99 ns 360.05 ns 360.12 ns]
                        thrpt:  [677.95 MiB/s 678.08 MiB/s 678.19 MiB/s]
prf/1KiB                time:   [795.15 ns 795.30 ns 795.46 ns]
                        thrpt:  [1.1989 GiB/s 1.1991 GiB/s 1.1994 GiB/s]
prf/16KiB               time:   [9.4178 µs 9.4193 µs 9.4209 µs]
                        thrpt:  [1.6197 GiB/s 1.6200 GiB/s 1.6202 GiB/s]
prf/1MiB                time:   [590.06 µs 590.18 µs 590.31 µs]
                        thrpt:  [1.6543 GiB/s 1.6547 GiB/s 1.6550 GiB/s]

stream/16B              time:   [346.19 ns 346.24 ns 346.28 ns]
                        thrpt:  [44.064 MiB/s 44.071 MiB/s 44.076 MiB/s]
stream/256B             time:   [531.95 ns 532.03 ns 532.13 ns]
                        thrpt:  [458.80 MiB/s 458.89 MiB/s 458.96 MiB/s]
stream/1KiB             time:   [1.2756 µs 1.2757 µs 1.2759 µs]
                        thrpt:  [765.42 MiB/s 765.50 MiB/s 765.57 MiB/s]
stream/16KiB            time:   [6.8756 µs 6.8767 µs 6.8778 µs]
                        thrpt:  [2.2185 GiB/s 2.2189 GiB/s 2.2193 GiB/s]
stream/1MiB             time:   [423.20 µs 423.32 µs 423.46 µs]
                        thrpt:  [2.3062 GiB/s 2.3069 GiB/s 2.3076 GiB/s]

aead/16B                time:   [533.15 ns 533.21 ns 533.27 ns]
                        thrpt:  [28.614 MiB/s 28.617 MiB/s 28.620 MiB/s]
aead/256B               time:   [719.99 ns 720.38 ns 720.77 ns]
                        thrpt:  [338.72 MiB/s 338.91 MiB/s 339.09 MiB/s]
aead/1KiB               time:   [1.5206 µs 1.5208 µs 1.5209 µs]
                        thrpt:  [642.10 MiB/s 642.16 MiB/s 642.21 MiB/s]
aead/16KiB              time:   [7.1835 µs 7.1845 µs 7.1856 µs]
                        thrpt:  [2.1235 GiB/s 2.1239 GiB/s 2.1241 GiB/s]
aead/1MiB               time:   [423.86 µs 424.02 µs 424.19 µs]
                        thrpt:  [2.3022 GiB/s 2.3031 GiB/s 2.3039 GiB/s]
```

(Benchmarks run on a GCE `c2-standard-4` with Intel Cascade Lake.)

## License

Copyright © 2022 Coda Hale

Distributed under the Apache License 2.0 or MIT License.
