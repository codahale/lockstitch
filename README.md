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
hash/16B                time:   [251.68 ns 251.82 ns 251.98 ns]
                        thrpt:  [60.555 MiB/s 60.595 MiB/s 60.628 MiB/s]
hash/256B               time:   [470.23 ns 470.42 ns 470.66 ns]
                        thrpt:  [518.72 MiB/s 518.98 MiB/s 519.20 MiB/s]
hash/1KiB               time:   [1.1756 µs 1.1761 µs 1.1767 µs]
                        thrpt:  [829.88 MiB/s 830.35 MiB/s 830.72 MiB/s]
hash/16KiB              time:   [6.3195 µs 6.3268 µs 6.3347 µs]
                        thrpt:  [2.4088 GiB/s 2.4118 GiB/s 2.4145 GiB/s]
hash/1MiB               time:   [165.44 µs 165.47 µs 165.52 µs]
                        thrpt:  [5.8999 GiB/s 5.9016 GiB/s 5.9029 GiB/s]

prf/16B                 time:   [253.12 ns 253.39 ns 253.71 ns]
                        thrpt:  [60.143 MiB/s 60.220 MiB/s 60.284 MiB/s]
prf/256B                time:   [268.17 ns 268.32 ns 268.50 ns]
                        thrpt:  [909.26 MiB/s 909.89 MiB/s 910.41 MiB/s]
prf/1KiB                time:   [432.36 ns 432.68 ns 433.05 ns]
                        thrpt:  [2.2022 GiB/s 2.2041 GiB/s 2.2057 GiB/s]
prf/16KiB               time:   [3.7362 µs 3.7388 µs 3.7425 µs]
                        thrpt:  [4.0772 GiB/s 4.0812 GiB/s 4.0841 GiB/s]
prf/1MiB                time:   [225.42 µs 225.61 µs 225.84 µs]
                        thrpt:  [4.3241 GiB/s 4.3285 GiB/s 4.3322 GiB/s]

stream/16B              time:   [347.75 ns 347.92 ns 348.10 ns]
                        thrpt:  [43.834 MiB/s 43.858 MiB/s 43.878 MiB/s]
stream/256B             time:   [563.27 ns 563.65 ns 564.09 ns]
                        thrpt:  [432.80 MiB/s 433.14 MiB/s 433.43 MiB/s]
stream/1KiB             time:   [1.3900 µs 1.3910 µs 1.3920 µs]
                        thrpt:  [701.56 MiB/s 702.07 MiB/s 702.56 MiB/s]
stream/16KiB            time:   [7.1060 µs 7.1166 µs 7.1287 µs]
                        thrpt:  [2.1405 GiB/s 2.1441 GiB/s 2.1473 GiB/s]
stream/1MiB             time:   [438.08 µs 438.64 µs 439.40 µs]
                        thrpt:  [2.2225 GiB/s 2.2263 GiB/s 2.2292 GiB/s]

aead/16B                time:   [530.27 ns 530.79 ns 531.44 ns]
                        thrpt:  [28.712 MiB/s 28.747 MiB/s 28.775 MiB/s]
aead/256B               time:   [736.94 ns 737.17 ns 737.43 ns]
                        thrpt:  [331.07 MiB/s 331.19 MiB/s 331.29 MiB/s]
aead/1KiB               time:   [1.6235 µs 1.6241 µs 1.6249 µs]
                        thrpt:  [601.00 MiB/s 601.28 MiB/s 601.51 MiB/s]
aead/16KiB              time:   [7.2435 µs 7.2503 µs 7.2582 µs]
                        thrpt:  [2.1023 GiB/s 2.1046 GiB/s 2.1066 GiB/s]
aead/1MiB               time:   [431.37 µs 431.82 µs 432.32 µs]
                        thrpt:  [2.2589 GiB/s 2.2615 GiB/s 2.2638 GiB/s]
```

(Benchmarks run on a GCE `n2-standard-4` with an Intel Ice Lake CPU.)

## License

Copyright © 2022 Coda Hale

Distributed under the Apache License 2.0 or MIT License.
