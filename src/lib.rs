#![cfg_attr(not(feature = "std"), no_std)]
#![doc = include_str!("../README.md")]
#![warn(missing_docs)]

use core::fmt::Debug;

use crate::aegis_128l::Aegis128L;

use hmac::{Hmac, KeyInit as _, Mac as _};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

mod aegis_128l;
mod intrinsics;

#[cfg(feature = "docs")]
#[doc = include_str!("../design.md")]
pub mod design {}

#[cfg(feature = "docs")]
#[doc = include_str!("../perf.md")]
pub mod perf {}

/// The length of an authentication tag in bytes.
pub const TAG_LEN: usize = 16;

/// A stateful object providing fine-grained symmetric-key cryptographic services like hashing,
/// message authentication codes, pseudo-random functions, authenticated encryption, and more.
#[derive(Clone)]
pub struct Protocol {
    state: [u8; 32],
}

impl Protocol {
    /// Creates a new protocol with the given domain.
    pub fn new(domain: &str) -> Protocol {
        // The initial state is extracted directly from the domain separation string using a fixed
        // key.
        //
        //     state = HMAC(HMAC("", "lockstitch lockstitch lockstitch"), prk)
        let mut h = Hmac::<Sha256>::new_from_slice(SALT).expect("should be valid HMAC key");
        h.update(domain.as_bytes());
        Protocol { state: h.finalize().into_bytes().into() }
    }

    /// Mixes the given label and slice into the protocol state.
    pub fn mix(&mut self, label: &str, input: &[u8]) {
        // Extract a PRK from the protocol's state, the operation code, the label, and the input,
        // using an unambiguous encoding to prevent collisions:
        //
        //     prk = HMAC(state, 0x01 || left_encode(|label|) || label || input)
        let mut h = Hmac::<Sha256>::new_from_slice(&self.state).expect("should be valid HMAC key");
        h.update(&[OpCode::Mix as u8]);
        h.update(left_encode(&mut [0u8; 9], label.len() as u64 * 8));
        h.update(label.as_bytes());
        h.update(input);
        let prk = h.finalize_reset().into_bytes();

        // Extract a new state value from the protocol's old state and the PRK:
        //
        //     state′ = HMAC(state, prk)
        //
        // This preserves the invariant that the protocol state is the HMAC output of two uniform
        // random keys.
        h.update(&prk);
        self.state = h.finalize().into_bytes().into();
    }

    /// Moves the protocol into a [`std::io::Write`] implementation, mixing all written data in a
    /// single operation and passing all writes to `inner`.
    ///
    /// Equivalent to buffering all written data in a slice and passing it to [`Protocol::mix`].
    ///
    /// Use [`MixWriter::into_inner`] to finish the operation and recover the protocol and `inner`.
    #[cfg(feature = "std")]
    pub fn mix_writer<W: std::io::Write>(self, label: &str, inner: W) -> MixWriter<W> {
        // Hash the initial prefix of the mix operation, then hand off to MixWriter.
        let mut h = Hmac::<Sha256>::new_from_slice(&self.state).expect("should be valid HMAC key");
        h.update(&[OpCode::Mix as u8]);
        h.update(left_encode(&mut [0u8; 9], label.len() as u64 * 8));
        h.update(label.as_bytes());
        MixWriter { h, inner }
    }

    /// Derives pseudorandom output from the protocol's current state, the label, and the output
    /// length, then ratchets the protocol's state with the label and output length.
    pub fn derive(&mut self, label: &str, out: &mut [u8]) {
        // Extract a PRK from the protocol's state, the operation code, the label, and the output
        // length, using an unambiguous encoding to prevent collisions:
        //
        //     prk = HMAC(state, 0x02 || left_encode(|label|) || label || left_encode(|out|))
        let mut h = Hmac::<Sha256>::new_from_slice(&self.state).expect("should be valid HMAC key");
        h.update(&[OpCode::Derive as u8]);
        h.update(left_encode(&mut [0u8; 9], label.len() as u64 * 8));
        h.update(label.as_bytes());
        h.update(left_encode(&mut [0u8; 9], out.len() as u64 * 8));
        let mut prk = h.finalize_reset().into_bytes();

        // Use the PRK to encrypt all zeroes with AEGIS-128L.
        let (k, n) = prk.split_at(16);
        let mut aegis = Aegis128L::new(k, n);
        aegis.prf(out);

        // Extract a new state value from the protocol's old state and the PRK:
        //
        //     state′ = HMAC(state, prk)
        //
        // This preserves the invariant that the protocol state is the HMAC output of two uniform
        // random keys.
        h.update(&prk);
        prk.zeroize();
        self.state = h.finalize().into_bytes().into();
    }

    /// Derives output from the protocol's current state and returns it as an `N`-byte array.
    #[inline]
    pub fn derive_array<const N: usize>(&mut self, label: &str) -> [u8; N] {
        let mut out = [0u8; N];
        self.derive(label, &mut out);
        out
    }

    /// Encrypts the given slice in place using the protocol's current state as the key, then
    /// ratchets the protocol's state using the label and input.
    pub fn encrypt(&mut self, label: &str, in_out: &mut [u8]) {
        // Extract a data encryption key from the protocol's state, the operation code, the label,
        // and the output length, using an unambiguous encoding to prevent collisions:
        //
        //     dek = HMAC(state, 0x03 || left_encode(|label|) || label || left_encode(|out|))
        let mut h = Hmac::<Sha256>::new_from_slice(&self.state).expect("should be valid HMAC key");
        h.update(&[OpCode::Crypt as u8]);
        h.update(left_encode(&mut [0u8; 9], label.len() as u64 * 8));
        h.update(label.as_bytes());
        h.update(left_encode(&mut [0u8; 9], in_out.len() as u64 * 8));
        let mut dek = h.finalize_reset().into_bytes();

        // Use the DEK to encrypt the plaintext with AEGIS-128L.
        let (k, n) = dek.split_at(16);
        let mut aegis = Aegis128L::new(k, n);
        dek.zeroize();
        aegis.encrypt(in_out);
        let (_, tag256) = aegis.finalize();

        // Extract a PRK from the protocol's state and the 256-bit AEGIS-128L tag and use it to
        // extract a new protocol state:
        //
        //     prk = HMAC(state, tag256)
        //     state′ = HMAC(state, prk)
        //
        // This preserves the invariant that the protocol state is the HMAC output of two uniform
        // random keys.
        h.update(&tag256);
        let prk = h.finalize_reset().into_bytes();
        h.update(&prk);
        self.state = h.finalize().into_bytes().into();
    }

    /// Decrypts the given slice in place using the protocol's current state as the key, then
    /// ratchets the protocol's state using the label and input.
    pub fn decrypt(&mut self, label: &str, in_out: &mut [u8]) {
        // Extract a data encryption key from the protocol's state, the operation code, the label,
        // and the output length, using an unambiguous encoding to prevent collisions:
        //
        //     dek = HMAC(state, 0x03 || left_encode(|label|) || label || left_encode(|out|))
        let mut h = Hmac::<Sha256>::new_from_slice(&self.state).expect("should be valid HMAC key");
        h.update(&[OpCode::Crypt as u8]);
        h.update(left_encode(&mut [0u8; 9], label.len() as u64 * 8));
        h.update(label.as_bytes());
        h.update(left_encode(&mut [0u8; 9], in_out.len() as u64 * 8));
        let mut dek = h.finalize_reset().into_bytes();

        // Use the DEK to decrypt the ciphertext with AEGIS-128L.
        let (k, n) = dek.split_at(16);
        let mut aegis = Aegis128L::new(k, n);
        dek.zeroize();
        aegis.decrypt(in_out);
        let (_, tag256) = aegis.finalize();

        // Extract a PRK from the protocol's state and the 256-bit AEGIS-128L tag and use it to
        // extract a new protocol state:
        //
        //     prk = HMAC(state, tag256)
        //     state′ = HMAC(state, prk)
        //
        // This preserves the invariant that the protocol state is the HMAC output of two uniform
        // random keys.
        h.update(&tag256);
        let prk = h.finalize_reset().into_bytes();
        h.update(&prk);
        self.state = h.finalize().into_bytes().into();
    }

    /// Encrypts the given slice in place using the protocol's current state as the key, appending
    /// an authentication tag of [`TAG_LEN`] bytes, then ratchets the protocol's state using the
    /// label and input.
    pub fn seal(&mut self, label: &str, in_out: &mut [u8]) {
        // Split the buffer into plaintext and tag.
        let (in_out, tag128_out) = in_out.split_at_mut(in_out.len() - TAG_LEN);

        // Extract a data encryption key from the protocol's state, the operation code, the label,
        // and the output length, using an unambiguous encoding to prevent collisions:
        //
        //     dek = HMAC(state, 0x04 || left_encode(|label|) || label || left_encode(|out|))
        let mut h = Hmac::<Sha256>::new_from_slice(&self.state).expect("should be valid HMAC key");
        h.update(&[OpCode::AuthCrypt as u8]);
        h.update(left_encode(&mut [0u8; 9], label.len() as u64 * 8));
        h.update(label.as_bytes());
        h.update(left_encode(&mut [0u8; 9], in_out.len() as u64 * 8));
        let mut dek = h.finalize_reset().into_bytes();

        // Use the DEK to encrypt the plaintext with AEGIS-128L.
        let (k, n) = dek.split_at(16);
        let mut aegis = Aegis128L::new(k, n);
        dek.zeroize();
        aegis.encrypt(in_out);
        let (tag128, tag256) = aegis.finalize();

        // Append the 128-bit AEGIS-128L tag to the ciphertext.
        tag128_out.copy_from_slice(&tag128);

        // Extract a PRK from the protocol's state and the 256-bit AEGIS-128L tag and use it to
        // extract a new protocol state:
        //
        //     prk = HMAC(state, tag256)
        //     state′ = HMAC(state, prk)
        //
        // This preserves the invariant that the protocol state is the HMAC output of two uniform
        // random keys.
        h.update(&tag256);
        let prk = h.finalize_reset().into_bytes();
        h.update(&prk);
        self.state = h.finalize().into_bytes().into();
    }

    /// Decrypts the given slice in place using the protocol's current state as the key, verifying
    /// the final [`TAG_LEN`] bytes as an authentication tag, then ratchets the protocol's state
    /// using the label and input.
    ///
    /// Returns the plaintext slice of `in_out` if the input was authenticated.
    #[must_use]
    pub fn open<'ct>(&mut self, label: &str, in_out: &'ct mut [u8]) -> Option<&'ct [u8]> {
        // Split the buffer into ciphertext and tag.
        let (in_out, tag128_in) = in_out.split_at_mut(in_out.len() - TAG_LEN);

        // Extract a data encryption key from the protocol's state, the operation code, the label,
        // and the output length, using an unambiguous encoding to prevent collisions:
        //
        //     dek = HMAC(state, 0x04 || left_encode(|label|) || label || left_encode(|out|))
        let mut h = Hmac::<Sha256>::new_from_slice(&self.state).expect("should be valid HMAC key");
        h.update(&[OpCode::AuthCrypt as u8]);
        h.update(left_encode(&mut [0u8; 9], label.len() as u64 * 8));
        h.update(label.as_bytes());
        h.update(left_encode(&mut [0u8; 9], in_out.len() as u64 * 8));
        let mut dek = h.finalize_reset().into_bytes();

        // Use the DEK to decrypt the ciphertext with AEGIS-128L.
        let (k, n) = dek.split_at(16);
        let mut aegis = Aegis128L::new(k, n);
        dek.zeroize();
        aegis.decrypt(in_out);
        let (tag128, tag256) = aegis.finalize();

        // Extract a PRK from the protocol's state and the 256-bit AEGIS-128L tag and use it to
        // extract a new protocol state:
        //
        //     prk = HMAC(state, tag256)
        //     state′ = HMAC(state, prk)
        //
        // This preserves the invariant that the protocol state is the HMAC output of two uniform
        // random keys.
        h.update(&tag256);
        let prk = h.finalize_reset().into_bytes();
        h.update(&prk);
        self.state = h.finalize().into_bytes().into();

        // Check the tag against the counterfactual tag in constant time.
        if tag128_in.ct_eq(&tag128).into() {
            // If the tag is verified, then the ciphertext is authentic. Return the slice of the
            // input which contains the plaintext.
            Some(in_out)
        } else {
            // Otherwise, the ciphertext is inauthentic and we zero out the inauthentic plaintext to
            // avoid bugs where the caller forgets to check the return value of this function and
            // discloses inauthentic plaintext.
            in_out.zeroize();
            None
        }
    }
}

impl Debug for Protocol {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Protocol").finish_non_exhaustive()
    }
}

impl Zeroize for Protocol {
    fn zeroize(&mut self) {
        self.state.zeroize();
    }
}

impl ZeroizeOnDrop for Protocol {}

impl Drop for Protocol {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// HMAC("", "lockstitch lockstitch lockstitch")
const SALT: &[u8; 32] = &[
    220, 87, 54, 63, 227, 165, 27, 245, 65, 144, 247, 188, 40, 15, 101, 174, 80, 197, 19, 248, 7,
    216, 209, 168, 247, 171, 219, 147, 63, 135, 63, 1,
];

/// All Lockstitch operation types.
#[derive(Debug, Clone, Copy)]
enum OpCode {
    /// Mix a labeled input into the protocol's state.
    Mix = 0x01,
    /// Derive a labeled output from the protocol's state.
    Derive = 0x02,
    /// Encrypt or decrypt a labeled input using the protocol's state as a key.
    Crypt = 0x03,
    /// Seal or open a labeled input using the protocol's state as a key.
    AuthCrypt = 0x04,
}

/// A [`std::io::Write`] implementation which combines all written data into a single `Mix`
/// operation and passes all writes to an inner writer.
#[cfg(feature = "std")]
pub struct MixWriter<W> {
    h: Hmac<Sha256>,
    inner: W,
}

#[cfg(feature = "std")]
impl<W: Debug> Debug for MixWriter<W> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MixWriter").field("inner", &self.inner).finish_non_exhaustive()
    }
}

#[cfg(feature = "std")]
impl<W: std::io::Write> MixWriter<W> {
    /// Finishes the `Mix` operation and returns the inner [`Protocol`] and writer.
    #[inline]
    pub fn into_inner(mut self) -> (Protocol, W) {
        // Finalize the hasher into a PRK.
        let prk = self.h.finalize_reset().into_bytes();
        // Extract a new state value from the protocol's state and the PRK.
        (Protocol { state: self.h.chain_update(prk).finalize().into_bytes().into() }, self.inner)
    }
}

#[cfg(feature = "std")]
impl<W: std::io::Write> std::io::Write for MixWriter<W> {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // Hash the slice.
        self.h.update(buf);
        // Pass the slice to the inner writer and return the result.
        self.inner.write(buf)
    }

    #[inline]
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Encodes a value using [NIST SP 800-185][]'s `left_encode`.
///
/// [NIST SP 800-185]: https://www.nist.gov/publications/sha-3-derived-functions-cshake-kmac-tuplehash-and-parallelhash
#[inline]
fn left_encode(buf: &mut [u8; 9], value: u64) -> &[u8] {
    let len = buf.len();
    buf[1..].copy_from_slice(&value.to_be_bytes());
    let n = (len - 1 - value.leading_zeros() as usize / 8).max(1);
    buf[len - n - 1] = n as u8;
    &buf[len - n - 1..]
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use std::io::{self, Cursor};

    use expect_test::expect;

    use super::*;

    #[test]
    fn known_answers() {
        let mut protocol = Protocol::new("com.example.kat");
        protocol.mix("first", b"one");
        protocol.mix("second", b"two");

        expect!["aa6167910242b3da"].assert_eq(&hex::encode(protocol.derive_array::<8>("third")));

        let mut plaintext = b"this is an example".to_vec();
        protocol.encrypt("fourth", &mut plaintext);
        expect!["90895fd71148d750fedbed8331c0f582f526"].assert_eq(&hex::encode(plaintext));

        let plaintext = b"this is an example";
        let mut sealed = vec![0u8; plaintext.len() + TAG_LEN];
        sealed[..plaintext.len()].copy_from_slice(plaintext);
        protocol.seal("fifth", &mut sealed);

        expect!["20f0c227e9a9bbf36e9fcc0cde34e7957877adf56b8d1a985ed83af4f3caa9ef7d3c"]
            .assert_eq(&hex::encode(sealed));

        expect!["5069bce9a1befaba"].assert_eq(&hex::encode(protocol.derive_array::<8>("sixth")));
    }

    #[test]
    fn readers() {
        let mut slices = Protocol::new("com.example.streams");
        slices.mix("first", b"one");
        slices.mix("second", b"two");

        let streams = Protocol::new("com.example.streams");
        let mut streams_write = streams.mix_writer("first", io::sink());
        io::copy(&mut Cursor::new(b"one"), &mut streams_write).expect("should be infallible");
        let (streams, _) = streams_write.into_inner();

        let mut output = Vec::new();
        let mut streams_write = streams.mix_writer("second", &mut output);
        io::copy(&mut Cursor::new(b"two"), &mut streams_write).expect("should be infallible");
        let (mut streams, output) = streams_write.into_inner();

        assert_eq!(slices.derive_array::<16>("third"), streams.derive_array::<16>("third"));
        assert_eq!(b"two".as_slice(), output);
    }

    #[test]
    fn edge_case() {
        let mut sender = Protocol::new("");
        let mut message = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        sender.encrypt("message", &mut message);
        let tag_s = sender.derive_array::<TAG_LEN>("tag");

        let mut receiver = Protocol::new("");
        receiver.decrypt("message", &mut message);
        let tag_r = receiver.derive_array::<TAG_LEN>("tag");

        assert_eq!(message, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(tag_s, tag_r);
    }

    #[test]
    fn encoded_label_injective() {
        bolero::check!().with_type::<(Vec<u8>, Vec<u8>)>().cloned().for_each(|(a, b)| {
            let mut a_e = Vec::new();
            a_e.extend_from_slice(left_encode(&mut [0u8; 9], a.len() as u64 * 8));
            a_e.extend_from_slice(&a);

            let mut b_e = Vec::new();
            b_e.extend_from_slice(left_encode(&mut [0u8; 9], b.len() as u64 * 8));
            b_e.extend_from_slice(&b);

            if a == b {
                assert_eq!(a_e, b_e, "equal labels must have equal encoded forms");
            } else {
                assert_ne!(a_e, b_e, "non-equal labels must have non-equal encoded forms");
            }
        });
    }

    #[test]
    fn left_encode_injective() {
        bolero::check!().with_type::<(u64, u64)>().cloned().for_each(|(a, b)| {
            let mut buf_a = [0u8; 9];
            let mut buf_b = [0u8; 9];

            let a_e = left_encode(&mut buf_a, a);
            let b_e = left_encode(&mut buf_b, b);

            if a == b {
                assert_eq!(a_e, b_e);
            } else {
                assert_ne!(a_e, b_e);
            }
        });
    }

    #[test]
    fn left_encode_test_vectors() {
        let mut buf = [0; 9];

        assert_eq!(left_encode(&mut buf, 0), [1, 0]);

        assert_eq!(left_encode(&mut buf, 128), [1, 128]);

        assert_eq!(left_encode(&mut buf, 65536), [3, 1, 0, 0]);

        assert_eq!(left_encode(&mut buf, 4096), [2, 16, 0]);

        assert_eq!(
            left_encode(&mut buf, 18446744073709551615),
            [8, 255, 255, 255, 255, 255, 255, 255, 255]
        );

        assert_eq!(left_encode(&mut buf, 12345), [2, 48, 57]);
    }

    #[test]
    fn check_salt() {
        let salt: [u8; 32] = Hmac::<Sha256>::new_from_slice(b"")
            .expect("should be a valid HMAC key")
            .chain_update(b"lockstitch")
            .finalize()
            .into_bytes()
            .into();
        assert_eq!(SALT, &salt);
    }
}
