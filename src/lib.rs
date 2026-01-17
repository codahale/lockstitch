#![doc = include_str!("../README.md")]
#![warn(missing_docs)]

use std::{fmt, mem};

use aws_lc_rs::aead::{AES_128_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::cipher::{AES_128, EncryptingKey, EncryptionContext, UnboundCipherKey};
use aws_lc_rs::constant_time::verify_slices_are_equal;
use aws_lc_rs::digest::{Context, SHA256};

/// The length of an authentication tag in bytes.
pub const TAG_LEN: usize = 16;

/// A stateful object providing fine-grained symmetric-key cryptographic services like hashing,
/// message authentication codes, pseudo-random functions, authenticated encryption, and more.
#[derive(Clone)]
pub struct Protocol {
    transcript: Context,
}

impl Protocol {
    /// Creates a new protocol with the given domain.
    pub fn new(domain: &str) -> Protocol {
        // Initialize an empty transcript.
        let mut transcript = Context::new(&SHA256);

        // Append the operation metadata to the transcript.
        let mut buf = [OpCode::Init as u8; 10];
        transcript.update(left_encode(&mut buf, 1, domain.len() as u64 * 8));
        transcript.update(domain.as_bytes());
        Protocol { transcript }
    }

    /// Mixes the given label and slice into the protocol state.
    pub fn mix(&mut self, label: &str, input: &[u8]) {
        // Append the operation metadata and data to the transcript.
        let mut buf = [OpCode::Mix as u8; 10];
        self.transcript.update(left_encode(&mut buf, 1, label.len() as u64 * 8));
        self.transcript.update(label.as_bytes());
        self.transcript.update(left_encode(&mut buf, 0, input.len() as u64 * 8));
        self.transcript.update(input);
    }

    /// Derives pseudorandom output from the protocol's current state, the label, and the output
    /// length, then ratchets the protocol's state with the label and output length.
    pub fn derive(&mut self, label: &str, out: &mut [u8]) {
        const MAX_DERIVE: usize = 64 * 1024 * 1024 * 1024;
        assert!(out.len() < MAX_DERIVE, "derive operations are limited to 64 GiB of output");

        // Append the operation metadata to the transcript.
        let mut buf = [OpCode::Derive as u8; 10];
        self.transcript.update(left_encode(&mut buf, 1, label.len() as u64 * 8));
        self.transcript.update(label.as_bytes());
        self.transcript.update(left_encode(&mut buf, 0, out.len() as u64 * 8));

        // Expand a PRF key.
        let mut prf_key = [0u8; 16];
        Self::expand(self.transcript.clone(), "prf key", &mut prf_key);

        // Expand n bytes of AES-128-CTR keystream for PRF output.
        out.fill(0);
        aes_ctr(&prf_key, &[0u8; 16], out);

        // Ratchet the transcript.
        self.ratchet();
    }

    /// Derives output from the protocol's current state and returns it as an `N`-byte array.
    #[inline]
    pub fn derive_array<const N: usize>(&mut self, label: &str) -> [u8; N] {
        let mut out = [0; N];
        self.derive(label, &mut out);
        out
    }

    /// Encrypts the given slice in place using the protocol's current state as the key, then
    /// ratchets the protocol's state using the label and input.
    pub fn encrypt(&mut self, label: &str, in_out: &mut [u8]) {
        // Append the operation metadata to the transcript.
        let mut buf = [OpCode::Crypt as u8; 10];
        self.transcript.update(left_encode(&mut buf, 1, label.len() as u64 * 8));
        self.transcript.update(label.as_bytes());
        self.transcript.update(left_encode(&mut buf, 0, in_out.len() as u64 * 8));

        // Expand a data encryption key and a data authentication key from the transcript.
        let (mut dek, mut dak) = ([0u8; 16], [0u8; 16]);
        Self::expand(self.transcript.clone(), "data encryption key", &mut dek);
        Self::expand(self.transcript.clone(), "data authentication key", &mut dak);

        // Calculate an AES-128-GMAC authenticator of the plaintext.
        let auth = aes_gmac(&dak, in_out);

        // Append the authenticator to the transcript.
        self.transcript.update(&auth);

        // Encrypt the plaintext using AES-128-CTR.
        aes_ctr(&dek, &[0u8; 16], in_out);

        // Ratchet the transcript.
        self.ratchet();
    }

    /// Decrypts the given slice in place using the protocol's current state as the key, then
    /// ratchets the protocol's state using the label and input.
    pub fn decrypt(&mut self, label: &str, in_out: &mut [u8]) {
        // Append the operation metadata to the transcript.
        let mut buf = [OpCode::Crypt as u8; 10];
        self.transcript.update(left_encode(&mut buf, 1, label.len() as u64 * 8));
        self.transcript.update(label.as_bytes());
        self.transcript.update(left_encode(&mut buf, 0, in_out.len() as u64 * 8));

        // Expand a data encryption key and a data authentication key from the transcript.
        let (mut dek, mut dak) = ([0u8; 16], [0u8; 16]);
        Self::expand(self.transcript.clone(), "data encryption key", &mut dek);
        Self::expand(self.transcript.clone(), "data authentication key", &mut dak);

        // Decrypt the plaintext using AES-128-CTR.
        aes_ctr(&dek, &[0u8; 16], in_out);

        // Calculate an AES-128-GMAC authenticator of the plaintext.
        let auth = aes_gmac(&dak, in_out);

        // Append the authenticator to the transcript.
        self.transcript.update(&auth);

        // Ratchet the transcript.
        self.ratchet();
    }

    /// Encrypts the given slice in place using the protocol's current state as the key, appending
    /// an authentication tag of [`TAG_LEN`] bytes, then ratchets the protocol's state using the
    /// label and input.
    pub fn seal(&mut self, label: &str, in_out: &mut [u8]) {
        let (in_out, tag) = in_out.split_at_mut(in_out.len() - TAG_LEN);

        // Append the operation metadata to the transcript.
        let mut buf = [OpCode::AuthCrypt as u8; 10];
        self.transcript.update(left_encode(&mut buf, 1, label.len() as u64 * 8));
        self.transcript.update(label.as_bytes());
        self.transcript.update(left_encode(&mut buf, 0, in_out.len() as u64 * 8));

        // Expand a data encryption key and a data authentication key from the transcript.
        let (mut dek, mut dak) = ([0u8; 16], [0u8; 16]);
        Self::expand(self.transcript.clone(), "data encryption key", &mut dek);
        Self::expand(self.transcript.clone(), "data authentication key", &mut dak);

        // Calculate an AES-128-GMAC authenticator of the plaintext.
        let auth = aes_gmac(&dak, in_out);

        // Append the authenticator to the transcript.
        self.transcript.update(&auth);

        // Expand an authentication tag.
        Self::expand(self.transcript.clone(), "authentication tag", tag);

        // Encrypt the plaintext using AES-128-CTR with the tag as the IV.
        aes_ctr(&dek, tag, in_out);

        // Ratchet the transcript.
        self.ratchet();
    }

    /// Decrypts the given slice in place using the protocol's current state as the key, verifying
    /// the final [`TAG_LEN`] bytes as an authentication tag, then ratchets the protocol's state
    /// using the label and input.
    ///
    /// Returns the plaintext slice of `in_out` if the input was authenticated.
    #[must_use]
    pub fn open<'ct>(&mut self, label: &str, in_out: &'ct mut [u8]) -> Option<&'ct [u8]> {
        let (in_out, tag) = in_out.split_at_mut(in_out.len() - TAG_LEN);

        // Append the operation metadata to the transcript.
        let mut buf = [OpCode::AuthCrypt as u8; 10];
        self.transcript.update(left_encode(&mut buf, 1, label.len() as u64 * 8));
        self.transcript.update(label.as_bytes());
        self.transcript.update(left_encode(&mut buf, 0, in_out.len() as u64 * 8));

        // Expand a data encryption key and a data authentication key from the transcript.
        let (mut dek, mut dak) = ([0u8; 16], [0u8; 16]);
        Self::expand(self.transcript.clone(), "data encryption key", &mut dek);
        Self::expand(self.transcript.clone(), "data authentication key", &mut dak);

        // Decrypt the ciphertext using AES-128-CTR with the tag as the IV.
        aes_ctr(&dek, tag, in_out);

        // Calculate an AES-128-GMAC authenticator of the plaintext.
        let auth = aes_gmac(&dak, in_out);

        // Append the authenticator to the transcript.
        self.transcript.update(&auth);

        // Expand a counterfactual authentication tag.
        let mut tag_p = [0u8; TAG_LEN];
        Self::expand(self.transcript.clone(), "authentication tag", &mut tag_p);

        // Ratchet the transcript.
        self.ratchet();

        // Compare the tag and the counterfactual tag in constant time.
        if verify_slices_are_equal(tag, &tag_p).is_ok() {
            // If the tag is verified, then the ciphertext is authentic. Return the slice of the
            // input which contains the plaintext.
            Some(in_out)
        } else {
            // Otherwise, the ciphertext is inauthentic, and we zero out the inauthentic plaintext
            // to avoid bugs where the caller forgets to check the return value of this function and
            // discloses inauthentic plaintext.
            in_out.fill(0);
            None
        }
    }

    /// Replaces the protocol's transcript with a ratchet operation code and a ratchet key derived
    /// from the previous protocol transcript.
    fn ratchet(&mut self) {
        // Replace the transcript with a blank one.
        let mut transcript = Context::new(&SHA256);
        mem::swap(&mut self.transcript, &mut transcript);

        // Expand a ratchet key from the old transcript.
        let mut rak = [0u8; 16];
        Self::expand(transcript, "ratchet key", &mut rak);

        // Append the operation metadata and data to the transcript.
        let mut buf = [OpCode::Ratchet as u8; 10];
        self.transcript.update(left_encode(&mut buf, 1, rak.len() as u64 * 8));
        self.transcript.update(&rak);
    }

    /// Appends an expand operation code, the label length, the label, and the requested output
    /// length to the given transcript, hashes it, and returns n (<=16) bytes of derived output.
    fn expand(mut transcript: Context, label: &str, out: &mut [u8]) {
        debug_assert!(out.len() <= 16, "expand output must be <= 16 bytes");

        // Append the operation metadata and data to the transcript copy.
        let mut buf = [OpCode::Expand as u8; 10];
        transcript.update(left_encode(&mut buf, 1, label.len() as u64 * 8));
        transcript.update(label.as_bytes());
        transcript.update(right_encode(&mut buf, 0, out.len() as u64 * 8));

        // Generate up to 16 bytes of output.
        let h = transcript.finish();
        out.copy_from_slice(&h.as_ref()[..out.len()]);
    }
}

impl fmt::Debug for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Protocol").finish_non_exhaustive()
    }
}

/// All Lockstitch operation types.
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
enum OpCode {
    /// Initialize a protocol with a domain separation string.
    Init = 0x01,
    /// Mix a labeled input into the protocol's transcript.
    Mix = 0x02,
    /// Derive a labeled output from the protocol's transcript.
    Derive = 0x03,
    /// Encrypt or decrypt a labeled input using the protocol's transcript as a key.
    Crypt = 0x04,
    /// Seal or open a labeled input using the protocol's transcript as a key.
    AuthCrypt = 0x05,
    /// Expand a pseudorandom bitstring from the protocol's transcript.
    Expand = 0x06,
    /// Ratchet the protocol's transcript.
    Ratchet = 0x07,
}

/// Encodes a value using [NIST SP 800-185]'s `left_encode`.
///
/// [NIST SP 800-185]: https://www.nist.gov/publications/sha-3-derived-functions-cshake-kmac-tuplehash-and-parallelhash
fn left_encode(buf: &mut [u8], offset: usize, mut value: u64) -> &[u8] {
    let n = 8 - ((value | 1).leading_zeros() / 8) as usize;
    value <<= (8 - n) * 8;
    let bytes = value.to_be_bytes();
    buf[offset] = n as u8;
    buf[offset + 1..offset + 1 + bytes.len()].copy_from_slice(&bytes);
    &buf[..offset + 1 + n]
}

/// Encodes a value using [NIST SP 800-185]'s `right_encode`.
///
/// [NIST SP 800-185]: https://www.nist.gov/publications/sha-3-derived-functions-cshake-kmac-tuplehash-and-parallelhash
fn right_encode(buf: &mut [u8], offset: usize, mut value: u64) -> &[u8] {
    let n = 8 - ((value | 1).leading_zeros() / 8) as usize;
    value <<= (8 - n) * 8;
    let bytes = value.to_be_bytes();
    buf[offset..offset + bytes.len()].copy_from_slice(&bytes);
    buf[offset + n] = n as u8;
    &buf[..offset + 1 + n]
}

/// Encrypts (or decrypts) an input with AES-128-CTR.
fn aes_ctr(key: &[u8], nonce: &[u8], in_out: &mut [u8]) {
    let key = UnboundCipherKey::new(&AES_128, key).expect("should be a valid AES-128 key");
    let key = EncryptingKey::ctr(key).expect("should be a valid AES-128-CTR key");
    let ctx = EncryptionContext::Iv128(nonce.try_into().expect("should be a valid AES-128-CTR IV"));
    key.less_safe_encrypt(in_out, ctx).expect("should perform AES-128-CTR");
}

/// Calculates an AES-128-GMAC authenticator of the input.
fn aes_gmac(key: &[u8], input: &[u8]) -> [u8; 16] {
    let key = UnboundKey::new(&AES_128_GCM, key).expect("should be a valid AES-128-GCM key");
    let key = LessSafeKey::new(key);
    key.seal_in_place_separate_tag(
        Nonce::assume_unique_for_key([0u8; 12]),
        Aad::from(input),
        &mut [],
    )
    .expect("should perform AES-128-GCM")
    .as_ref()
    .try_into()
    .expect("should be 16 bytes")
}

#[cfg(test)]
mod tests {
    use expect_test::expect;

    use super::*;

    #[test]
    fn known_answers() {
        let mut protocol = Protocol::new("com.example.kat");
        protocol.mix("first", b"one");
        protocol.mix("second", b"two");

        expect!["1b1eb6c50b7a0efa"].assert_eq(&hex::encode(protocol.derive_array::<8>("third")));

        let mut plaintext = b"this is an example".to_vec();
        protocol.encrypt("fourth", &mut plaintext);
        expect!["db1daa1bc9483166afc66e64e5ea755551a1"].assert_eq(&hex::encode(plaintext));

        let plaintext = b"this is an example";
        let mut sealed = vec![0u8; plaintext.len() + TAG_LEN];
        sealed[..plaintext.len()].copy_from_slice(plaintext);
        protocol.seal("fifth", &mut sealed);

        expect!["d02f72467272779eedff51ffd875d6a4c45537b38d3d56868af3acdb81c22e2fcd24"]
            .assert_eq(&hex::encode(sealed));

        expect!["04d8a4b236e5e7db"].assert_eq(&hex::encode(protocol.derive_array::<8>("sixth")));
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
            a_e.extend_from_slice(left_encode(&mut [0u8; 9], 0, a.len() as u64 * 8).as_ref());
            a_e.extend_from_slice(&a);

            let mut b_e = Vec::new();
            b_e.extend_from_slice(left_encode(&mut [0u8; 9], 0, b.len() as u64 * 8).as_ref());
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
            let a_e = left_encode(&mut buf_a, 0, a);
            let b_e = left_encode(&mut buf_b, 0, b);

            if a == b {
                assert_eq!(a_e, b_e);
            } else {
                assert_ne!(a_e, b_e);
            }
        });
    }

    #[test]
    fn left_encode_test_vectors() {
        let mut buf = [69u8; 10];

        assert_eq!(left_encode(&mut buf, 0, 0), [1, 0]);

        assert_eq!(left_encode(&mut buf, 0, 128), [1, 128]);

        assert_eq!(left_encode(&mut buf, 0, 65536), [3, 1, 0, 0]);

        assert_eq!(left_encode(&mut buf, 0, 4096), [2, 16, 0]);

        assert_eq!(
            left_encode(&mut buf, 0, 18446744073709551615),
            [8, 255, 255, 255, 255, 255, 255, 255, 255]
        );

        assert_eq!(left_encode(&mut buf, 0, 12345), [2, 48, 57]);
    }

    #[test]
    fn right_encode_test_vectors() {
        let mut buf = [69u8; 10];

        assert_eq!(right_encode(&mut buf, 0, 0), [0, 1]);

        assert_eq!(right_encode(&mut buf, 0, 128), [128, 1]);

        assert_eq!(right_encode(&mut buf, 0, 65536), [1, 0, 0, 3]);

        assert_eq!(right_encode(&mut buf, 0, 4096), [16, 0, 2]);

        assert_eq!(
            right_encode(&mut buf, 0, 18446744073709551615),
            [255, 255, 255, 255, 255, 255, 255, 255, 8]
        );

        assert_eq!(right_encode(&mut buf, 0, 12345), [48, 57, 2]);
    }
}
