#![cfg_attr(not(feature = "std"), no_std)]
#![doc = include_str!("../README.md")]
#![warn(missing_docs)]

use core::fmt::Debug;

use aws_lc_rs::{
    cipher::{
        AES_128, AES_128_KEY_LEN, DecryptingKey, DecryptionContext, EncryptingKey,
        EncryptionContext, UnboundCipherKey,
    },
    constant_time::verify_slices_are_equal,
    hmac::{Context as HmacContext, HMAC_SHA256, Key as HmacKey, sign as hmac},
};
use zeroize::{Zeroize, ZeroizeOnDrop};

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
        //     state = HMAC(HMAC("", "lockstitch"), domain)
        let state = hmac(&HmacKey::new(HMAC_SHA256, SALT), domain.as_bytes());
        Protocol { state: state.as_ref().try_into().expect("should be 32 bytes") }
    }

    /// Mixes the given label and slice into the protocol state.
    pub fn mix(&mut self, label: &str, input: &[u8]) {
        // Extract a PRK from the protocol's state, the operation code, the label, and the input,
        // using an unambiguous encoding to prevent collisions:
        //
        //     prk = HMAC(state, 0x01 || left_encode(|label|) || label || input)
        let mut h = HmacContext::with_key(&HmacKey::new(HMAC_SHA256, &self.state));
        h.update(&[OpCode::Mix as u8]);
        h.update(left_encode(&mut [0u8; 9], label.len() as u64 * 8));
        h.update(label.as_bytes());
        h.update(input);
        let prk = h.sign();

        // Extract a new state value from the protocol's old state and the PRK:
        //
        //     state′ = HMAC(state, prk)
        //
        // This preserves the invariant that the protocol state is the HMAC output of two uniform
        // random keys.
        self.state = hmac(&HmacKey::new(HMAC_SHA256, &self.state), prk.as_ref())
            .as_ref()
            .try_into()
            .expect("should be 32 bytes");
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
        let key = HmacKey::new(HMAC_SHA256, &self.state);
        let mut h = HmacContext::with_key(&key);
        h.update(&[OpCode::Mix as u8]);
        h.update(left_encode(&mut [0u8; 9], label.len() as u64 * 8));
        h.update(label.as_bytes());
        MixWriter { key, h, inner }
    }

    /// Derives pseudorandom output from the protocol's current state, the label, and the output
    /// length, then ratchets the protocol's state with the label and output length.
    pub fn derive(&mut self, label: &str, out: &mut [u8]) {
        // Extract a PRK from the protocol's state, the operation code, the label, and the output
        // length, using an unambiguous encoding to prevent collisions:
        //
        //     prk = HMAC(state, 0x02 || left_encode(|label|) || label || left_encode(|out|))
        let mut h = HmacContext::with_key(&HmacKey::new(HMAC_SHA256, &self.state));
        h.update(&[OpCode::Derive as u8]);
        h.update(left_encode(&mut [0u8; 9], label.len() as u64 * 8));
        h.update(label.as_bytes());
        h.update(left_encode(&mut [0u8; 9], out.len() as u64 * 8));
        let prk = h.sign();

        // Use the PRK to encrypt all zeroes with AES-128:
        //
        //     k || n = prk
        //     prf = AES-128-CTR(k, n, [0x00; N])
        out.zeroize();
        let (k, n) = prk.as_ref().split_at(AES_128_KEY_LEN);
        let key = UnboundCipherKey::new(&AES_128, k).expect("should be valid AES-128 key");
        let key = EncryptingKey::ctr(key).expect("should be valid CTR key");
        let ctx = EncryptionContext::Iv128(n.try_into().expect("should be 16 bytes"));
        key.less_safe_encrypt(out, ctx).expect("should encrypt");

        // Extract a new state value from the protocol's old state and the PRK:
        //
        //     state′ = HMAC(state, prk)
        //
        // This preserves the invariant that the protocol state is the HMAC output of two uniform
        // random keys.
        self.state = hmac(&HmacKey::new(HMAC_SHA256, &self.state), prk.as_ref())
            .as_ref()
            .try_into()
            .expect("should be 32 bytes");
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
        // Extract a data encryption key and data authentication key from the protocol's state, the
        // operation code, the label, and the output length, using an unambiguous encoding to
        // prevent collisions:
        //
        //     dek || dak = HMAC(state, 0x03 || left_encode(|label|) || label || left_encode(|out|))
        let mut h = HmacContext::with_key(&HmacKey::new(HMAC_SHA256, &self.state));
        h.update(&[OpCode::Crypt as u8]);
        h.update(left_encode(&mut [0u8; 9], label.len() as u64 * 8));
        h.update(label.as_bytes());
        h.update(left_encode(&mut [0u8; 9], in_out.len() as u64 * 8));
        let prk = h.sign();
        let (dek, dak) = prk.as_ref().split_at(AES_128_KEY_LEN);

        // Use the DEK to encrypt the plaintext with AES-128:
        //
        //     ciphertext = AES-128-CTR(dek, plaintext)
        let key = UnboundCipherKey::new(&AES_128, dek).expect("should be valid AES-128 key");
        let key = EncryptingKey::ctr(key).expect("should be valid CTR key");
        key.less_safe_encrypt(in_out, EncryptionContext::Iv128([0u8; 16].into()))
            .expect("should encrypt");

        // Use the DAK to extract a PRK from the ciphertext.
        //
        //     prk = HMAC-SHA-256(dak, ciphertext)
        let prk = hmac(&HmacKey::new(HMAC_SHA256, dak), in_out);

        // Use the PRK to extract a new protocol state:
        //
        //     state′ = HMAC(state, prk)
        //
        // This preserves the invariant that the protocol state is the HMAC output of two uniform
        // random keys.
        self.state = hmac(&HmacKey::new(HMAC_SHA256, &self.state), prk.as_ref())
            .as_ref()
            .try_into()
            .expect("should be 32 bytes");
    }

    /// Decrypts the given slice in place using the protocol's current state as the key, then
    /// ratchets the protocol's state using the label and input.
    pub fn decrypt(&mut self, label: &str, in_out: &mut [u8]) {
        // Extract a data encryption key and data authentication key from the protocol's state, the
        // operation code, the label, and the output length, using an unambiguous encoding to
        // prevent collisions:
        //
        //     dek || dak = HMAC(state, 0x03 || left_encode(|label|) || label || left_encode(|out|))
        let mut h = HmacContext::with_key(&HmacKey::new(HMAC_SHA256, &self.state));
        h.update(&[OpCode::Crypt as u8]);
        h.update(left_encode(&mut [0u8; 9], label.len() as u64 * 8));
        h.update(label.as_bytes());
        h.update(left_encode(&mut [0u8; 9], in_out.len() as u64 * 8));
        let prk = h.sign();
        let (dek, dak) = prk.as_ref().split_at(AES_128_KEY_LEN);

        // Use the DAK to extract a PRK from the ciphertext.
        //
        //     prk = HMAC-SHA-256(dak, ciphertext)
        let prk = hmac(&HmacKey::new(HMAC_SHA256, dak), in_out);

        // Use the PRK to extract a new protocol state:
        //
        //     state′ = HMAC(state, prk)
        //
        // This preserves the invariant that the protocol state is the HMAC output of two uniform
        // random keys.
        self.state = hmac(&HmacKey::new(HMAC_SHA256, &self.state), prk.as_ref())
            .as_ref()
            .try_into()
            .expect("should be 32 bytes");

        // Use the DEK to decrypt the ciphertext with AES-128.
        let key = UnboundCipherKey::new(&AES_128, dek).expect("should be valid AES-128 key");
        let key = DecryptingKey::ctr(key).expect("should be valid CTR key");
        key.decrypt(in_out, DecryptionContext::Iv128([0u8; 16].into())).expect("should decrypt");
    }

    /// Encrypts the given slice in place using the protocol's current state as the key, appending
    /// an authentication tag of [`TAG_LEN`] bytes, then ratchets the protocol's state using the
    /// label and input.
    pub fn seal(&mut self, label: &str, in_out: &mut [u8]) {
        // Split the buffer into plaintext and tag.
        let (in_out, tag128_out) = in_out.split_at_mut(in_out.len() - TAG_LEN);

        // Extract a data encryption key and data authentication key from the protocol's state, the
        // operation code, the label, and the output length, using an unambiguous encoding to
        // prevent collisions:
        //
        //     dek || dak = HMAC(state, 0x04 || left_encode(|label|) || label || left_encode(|out|))
        let mut h = HmacContext::with_key(&HmacKey::new(HMAC_SHA256, &self.state));
        h.update(&[OpCode::AuthCrypt as u8]);
        h.update(left_encode(&mut [0u8; 9], label.len() as u64 * 8));
        h.update(label.as_bytes());
        h.update(left_encode(&mut [0u8; 9], in_out.len() as u64 * 8));
        let prk = h.sign();
        let (dek, dak) = prk.as_ref().split_at(AES_128_KEY_LEN);

        // Use the DEK to encrypt the plaintext with AES-128:
        //
        //     ciphertext = AES-128-CTR(dek, plaintext)
        let key = UnboundCipherKey::new(&AES_128, dek).expect("should be valid AES-128 key");
        let key = EncryptingKey::ctr(key).expect("should be valid CTR key");
        key.less_safe_encrypt(in_out, EncryptionContext::Iv128([0u8; 16].into()))
            .expect("should encrypt");

        // Use the DAK to extract a PRK from the ciphertext.
        //
        //     prk = HMAC-SHA-256(dak, ciphertext)
        let prk = hmac(&HmacKey::new(HMAC_SHA256, dak), in_out);

        // Use the PRK to extract a new protocol state:
        //
        //     state′ = HMAC(state, prk)
        //
        // This preserves the invariant that the protocol state is the HMAC output of two uniform
        // random keys.
        self.state = hmac(&HmacKey::new(HMAC_SHA256, &self.state), prk.as_ref())
            .as_ref()
            .try_into()
            .expect("should be 32 bytes");

        // Use the first half of the PRK as an authentication tag.
        tag128_out.copy_from_slice(&prk.as_ref()[..TAG_LEN]);
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

        // Extract a data encryption key and data authentication key from the protocol's state, the
        // operation code, the label, and the output length, using an unambiguous encoding to
        // prevent collisions:
        //
        //     dek || dak = HMAC(state, 0x04 || left_encode(|label|) || label || left_encode(|out|))
        let mut h = HmacContext::with_key(&HmacKey::new(HMAC_SHA256, &self.state));
        h.update(&[OpCode::AuthCrypt as u8]);
        h.update(left_encode(&mut [0u8; 9], label.len() as u64 * 8));
        h.update(label.as_bytes());
        h.update(left_encode(&mut [0u8; 9], in_out.len() as u64 * 8));
        let prk = h.sign();
        let (dek, dak) = prk.as_ref().split_at(AES_128_KEY_LEN);

        // Use the DAK to extract a PRK from the ciphertext.
        //
        //     prk = HMAC-SHA-256(dak, ciphertext)
        let prk = hmac(&HmacKey::new(HMAC_SHA256, dak), in_out);

        // Use the PRK to extract a new protocol state:
        //
        //     state′ = HMAC(state, prk)
        //
        // This preserves the invariant that the protocol state is the HMAC output of two uniform
        // random keys.
        self.state = hmac(&HmacKey::new(HMAC_SHA256, &self.state), prk.as_ref())
            .as_ref()
            .try_into()
            .expect("should be 32 bytes");

        // Use the DEK to decrypt the ciphertext with AES-128.
        let key = UnboundCipherKey::new(&AES_128, dek).expect("should be valid AES-128 key");
        let key = DecryptingKey::ctr(key).expect("should be valid CTR key");
        key.decrypt(in_out, DecryptionContext::Iv128([0u8; 16].into())).expect("should decrypt");

        // Verify the authentication tag.
        if verify_slices_are_equal(tag128_in, &prk.as_ref()[..TAG_LEN]).is_ok() {
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

// HMAC("", "lockstitch")
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
    key: HmacKey,
    h: HmacContext,
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
        // Finalize the hasher into a PRK.
        let prk = self.h.sign();

        // Extract a new state value from the protocol's state and the PRK.
        let state = hmac(&self.key, prk.as_ref());

        (Protocol { state: state.as_ref().try_into().expect("should be 32 bytes") }, self.inner)
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

        expect!["f30a3c4582cf74b5"].assert_eq(&hex::encode(protocol.derive_array::<8>("third")));

        let mut plaintext = b"this is an example".to_vec();
        protocol.encrypt("fourth", &mut plaintext);
        expect!["cbc0743dbcd23d85d16221fc94ae677d29d9"].assert_eq(&hex::encode(plaintext));

        let plaintext = b"this is an example";
        let mut sealed = vec![0u8; plaintext.len() + TAG_LEN];
        sealed[..plaintext.len()].copy_from_slice(plaintext);
        protocol.seal("fifth", &mut sealed);

        expect!["d528450958cc411155822bf18cc8fce4293d8e7997a5f1cc86bbf3d8a91aaf17a462"]
            .assert_eq(&hex::encode(sealed));

        expect!["6ad071b6d832594a"].assert_eq(&hex::encode(protocol.derive_array::<8>("sixth")));
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
        let salt = hmac(&HmacKey::new(HMAC_SHA256, b""), b"lockstitch");
        assert_eq!(SALT, salt.as_ref());
    }
}
