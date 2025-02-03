#![cfg_attr(not(feature = "std"), no_std)]
#![doc = include_str!("../README.md")]
#![warn(missing_docs)]

use core::fmt::Debug;

use crate::aegis_128l::Aegis128L;

use cmov::CmovEq;
use hmac::{Hmac, Mac};
use sha2::Sha256;

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
    #[inline]
    pub fn new(domain: &str) -> Protocol {
        // The initial state is derived directly from the domain separation string using a fixed
        // salt.
        Protocol {
            state: Hmac::<Sha256>::new_from_slice(SALT)
                .expect("should be valid HMAC key")
                .chain_update(domain.as_bytes())
                .finalize()
                .into_bytes()
                .into(),
        }
    }

    /// Mixes the given label and slice into the protocol state.
    ///
    /// The resulting protocol state is cryptographically dependent on both the prior state of the
    /// protocol and the inputs to the mix operation. If either the prior state or the inputs are
    /// secret, the resulting protocol state is secret, even if all remaining data is
    /// attacker-controlled.
    #[inline]
    pub fn mix(&mut self, label: &str, input: &[u8]) {
        // Extract a new protocol state using the protocol's prior state as the key:
        //
        //      state' = HMAC(state, 0x01 || left_encode(|label|) || label || input)
        let mut h = Hmac::<Sha256>::new_from_slice(&self.state).expect("should be valid HMAC key");
        h.update(&[OpCode::Mix as u8]);
        h.update(left_encode(&mut [0u8; 9], label.len() as u64 * 8));
        h.update(label.as_bytes());
        h.update(input);
        self.state = h.finalize().into_bytes().into();
    }

    /// Moves the protocol into a [`std::io::Write`] implementation, mixing all written data in a
    /// single operation and passing all writes to `inner`.
    ///
    /// Equivalent to buffering all written data in a slice and passing it to [`Protocol::mix`].
    ///
    /// Use [`MixWriter::into_inner`] to finish the operation and recover the protocol and `inner`.
    #[inline]
    #[cfg(feature = "std")]
    pub fn mix_writer<W: std::io::Write>(self, label: &str, inner: W) -> MixWriter<W> {
        // Hash the initial prefix of the mix operation, then hand off to MixWriter.
        let mut h = Hmac::<Sha256>::new_from_slice(&self.state).expect("should be valid HMAC key");
        h.update(&[OpCode::Mix as u8]);
        h.update(left_encode(&mut [0u8; 9], label.len() as u64 * 8));
        h.update(label.as_bytes());
        MixWriter { h, inner }
    }

    /// Derives pseudorandom output from the protocol's current state.
    ///
    /// The output is dependent on the protocol's prior state, the label, and the length of `out`.
    /// This function is limited to 65,280 bytes of output.
    #[inline]
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
        let prk = h.finalize_reset().into_bytes();

        // Split the PRK into two halves and use them as key and nonce to initialize an AEGIS-128L
        // instance.
        let (k, n) = prk.split_at(16);
        let mut aegis = Aegis128L::new(k, n);

        // Encrypt all zeroes to produce the output.
        out.fill(0);
        aegis.encrypt(out);

        // Extract a new protocol state from protocol's old state and the PRK.
        h.update(&prk);
        self.state = h.finalize().into_bytes().into();
    }

    /// Derives output from the protocol's current state and returns it as an `N`-byte array.
    #[inline]
    pub fn derive_array<const N: usize>(&mut self, label: &str) -> [u8; N] {
        let mut out = [0u8; N];
        self.derive(label, &mut out);
        out
    }

    /// Encrypts the given slice in place.
    #[inline]
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
        let dek = h.finalize_reset().into_bytes();

        // Split the DEK into two halves and use them as key and nonce to initialize an AEGIS-128L
        // instance.
        let (k, n) = dek.split_at(16);
        let mut aegis = Aegis128L::new(k, n);

        // Encrypt the plaintext and finalize the 256-bit tag.
        aegis.encrypt(in_out);
        let (_, tag256) = aegis.finalize();

        // Extract a new protocol state from protocol's old state and the 256-bit tag.
        h.update(&tag256);
        self.state = h.finalize().into_bytes().into();
    }

    /// Decrypts the given slice in place.
    #[inline]
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
        let dek = h.finalize_reset().into_bytes();

        // Split the DEK into two halves and use them as key and nonce to initialize an AEGIS-128L
        // instance.
        let (k, n) = dek.split_at(16);
        let mut aegis = Aegis128L::new(k, n);

        // Decrypt the ciphertext and finalize the 256-bit tag.
        aegis.decrypt(in_out);
        let (_, tag256) = aegis.finalize();

        // Extract a new protocol state from protocol's old state and the 256-bit tag.
        h.update(&tag256);
        self.state = h.finalize().into_bytes().into();
    }

    /// Seals the given mutable slice in place.
    ///
    /// The last [`TAG_LEN`] bytes of the slice will be overwritten with the authentication tag.
    #[inline]
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
        let dek = h.finalize_reset().into_bytes();

        // Split the DEK into two halves and use them as key and nonce to initialize an AEGIS-128L
        // instance.
        let (k, n) = dek.split_at(16);
        let mut aegis = Aegis128L::new(k, n);

        // Encrypt the plaintext.
        aegis.encrypt(in_out);

        // Finalize the AEGIS-128L tags.
        let (tag128, tag256) = aegis.finalize();

        // Append the 128-bit AEGIS-128L tag to the ciphertext.
        tag128_out.copy_from_slice(&tag128);

        // Extract a new protocol state from protocol's old state and the 256-bit tag.
        h.update(&tag256);
        self.state = h.finalize().into_bytes().into();
    }

    /// Opens the given mutable slice in place. Returns the plaintext slice of `in_out` if the input
    /// was authenticated. The last [`TAG_LEN`] bytes of the slice will be unmodified.
    #[inline]
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
        let dek = h.finalize_reset().into_bytes();

        // Split the DEK into two halves and use them as key and nonce to initialize an AEGIS-128L
        // instance.
        let (k, n) = dek.split_at(16);
        let mut aegis = Aegis128L::new(k, n);

        // Decrypt the ciphertext.
        aegis.decrypt(in_out);

        // Finalize the AEGIS-128L tags.
        let (tag128, tag256) = aegis.finalize();

        // Extract a new protocol state from protocol's old state and the 256-bit tag.
        h.update(&tag256);
        self.state = h.finalize().into_bytes().into();

        // Check the tag against the counterfactual tag in constant time.
        if ct_eq(tag128_in, &tag128) {
            // If the tag is verified, then the ciphertext is authentic. Return the slice of the
            // input which contains the plaintext.
            Some(in_out)
        } else {
            // Otherwise, the ciphertext is inauthentic and we zero out the inauthentic plaintext to
            // avoid bugs where the caller forgets to check the return value of this function and
            // discloses inauthentic plaintext.
            in_out.fill(0);
            None
        }
    }
}

impl Debug for Protocol {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Protocol").finish_non_exhaustive()
    }
}

const SALT: &[u8; 32] = b"lockstitch lockstitch lockstitch";

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
    pub fn into_inner(self) -> (Protocol, W) {
        (Protocol { state: self.h.finalize().into_bytes().into() }, self.inner)
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

/// Compares two slices for equality in constant time.
#[inline]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    let mut res = 1;
    a.cmovne(b, 0, &mut res);
    res != 0
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

        expect!["eb55cdd9255671ef"].assert_eq(&hex::encode(protocol.derive_array::<8>("third")));

        let mut plaintext = b"this is an example".to_vec();
        protocol.encrypt("fourth", &mut plaintext);
        expect!["7c6861e2f45daddc97f1fd64afa794331590"].assert_eq(&hex::encode(plaintext));

        let plaintext = b"this is an example";
        let mut sealed = vec![0u8; plaintext.len() + TAG_LEN];
        sealed[..plaintext.len()].copy_from_slice(plaintext);
        protocol.seal("fifth", &mut sealed);

        expect!["f848a305a96cdcc588f41d91a0ce72d0498517ded5638f5fc1f45331d6e636e3fbd3"]
            .assert_eq(&hex::encode(sealed));

        expect!["fdcefea851f8c560"].assert_eq(&hex::encode(protocol.derive_array::<8>("sixth")));
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
}
