#![doc = include_str!("../README.md")]
#![warn(missing_docs)]

use core::fmt::Debug;

use openssl::cipher::Cipher;
use openssl::cipher_ctx::CipherCtx;
use openssl::hash::{Hasher, MessageDigest};
use openssl::memcmp;

/// The length of an authentication tag in bytes.
pub const TAG_LEN: usize = 16;

/// A stateful object providing fine-grained symmetric-key cryptographic services like hashing,
/// message authentication codes, pseudo-random functions, authenticated encryption, and more.
#[derive(Clone)]
pub struct Protocol {
    transcript: Hasher,
}

impl Protocol {
    /// Creates a new protocol with the given domain.
    pub fn new(domain: &str) -> Protocol {
        // Initialize an empty transcript.
        let mut transcript =
            Hasher::new(MessageDigest::sha512()).expect("should implement SHA-512");

        // Append the operation metadata to the transcript.
        let _ = transcript.update(&[OpCode::Init as u8]);
        let _ = transcript.update(left_encode(domain.len() as u64 * 8).as_ref());
        let _ = transcript.update(domain.as_bytes());
        Protocol { transcript }
    }

    /// Mixes the given label and slice into the protocol state.
    pub fn mix(&mut self, label: &str, input: &[u8]) {
        // Append the operation metadata and data to the transcript.
        let _ = self.transcript.update(&[OpCode::Mix as u8]);
        let _ = self.transcript.update(left_encode(label.len() as u64 * 8).as_ref());
        let _ = self.transcript.update(label.as_bytes());
        let _ = self.transcript.update(left_encode(input.len() as u64 * 8).as_ref());
        let _ = self.transcript.update(input);
    }

    /// Derives pseudorandom output from the protocol's current state, the label, and the output
    /// length, then ratchets the protocol's state with the label and output length.
    pub fn derive(&mut self, label: &str, out: &mut [u8]) {
        const MAX_DERIVE: usize = 64 * 1024 * 1024 * 1024;
        assert!(out.len() < MAX_DERIVE, "derive operations are limited to 64 GiB of output");

        // Append the operation metadata to the transcript.
        let _ = self.transcript.update(&[OpCode::Derive as u8]);
        let _ = self.transcript.update(left_encode(label.len() as u64 * 8).as_ref());
        let _ = self.transcript.update(label.as_bytes());
        let _ = self.transcript.update(left_encode(out.len() as u64 * 8).as_ref());

        // Expand a PRF key.
        let mut prf_key = [0u8; 32];
        self.expand("prf key", &mut prf_key);

        // Expand n bytes of AES-256-CTR keystream for PRF output.
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
        let _ = self.transcript.update(&[OpCode::Crypt as u8]);
        let _ = self.transcript.update(left_encode(label.len() as u64 * 8).as_ref());
        let _ = self.transcript.update(label.as_bytes());
        let _ = self.transcript.update(left_encode(in_out.len() as u64 * 8).as_ref());

        // Expand a data encryption key and a data authentication key from the transcript.
        let (mut dek, mut dak) = ([0u8; 32], [0u8; 32]);
        self.expand("data encryption key", &mut dek);
        self.expand("data authentication key", &mut dak);

        // Calculate an AES-256-GMAC authenticator of the plaintext.
        let auth = aes_gmac(&dak, in_out);

        // Append the authenticator to the transcript.
        let _ = self.transcript.update(&auth);

        // Encrypt the plaintext using AES-256-CTR.
        aes_ctr(&dek, &[0u8; 16], in_out);

        // Ratchet the transcript.
        self.ratchet();
    }

    /// Decrypts the given slice in place using the protocol's current state as the key, then
    /// ratchets the protocol's state using the label and input.
    pub fn decrypt(&mut self, label: &str, in_out: &mut [u8]) {
        // Append the operation metadata to the transcript.
        let _ = self.transcript.update(&[OpCode::Crypt as u8]);
        let _ = self.transcript.update(left_encode(label.len() as u64 * 8).as_ref());
        let _ = self.transcript.update(label.as_bytes());
        let _ = self.transcript.update(left_encode(in_out.len() as u64 * 8).as_ref());

        // Expand a data encryption key and a data authentication key from the transcript.
        let (mut dek, mut dak) = ([0u8; 32], [0u8; 32]);
        self.expand("data encryption key", &mut dek);
        self.expand("data authentication key", &mut dak);

        // Decrypt the plaintext using AES-256-CTR.
        aes_ctr(&dek, &[0u8; 16], in_out);

        // Calculate an AES-256-GMAC authenticator of the plaintext.
        let auth = aes_gmac(&dak, in_out);

        // Append the authenticator to the transcript.
        let _ = self.transcript.update(&auth);

        // Ratchet the transcript.
        self.ratchet();
    }

    /// Encrypts the given slice in place using the protocol's current state as the key, appending
    /// an authentication tag of [`TAG_LEN`] bytes, then ratchets the protocol's state using the
    /// label and input.
    pub fn seal(&mut self, label: &str, in_out: &mut [u8]) {
        let (in_out, tag) = in_out.split_at_mut(in_out.len() - TAG_LEN);

        // Append the operation metadata to the transcript.
        let _ = self.transcript.update(&[OpCode::AuthCrypt as u8]);
        let _ = self.transcript.update(left_encode(label.len() as u64 * 8).as_ref());
        let _ = self.transcript.update(label.as_bytes());
        let _ = self.transcript.update(left_encode(in_out.len() as u64 * 8).as_ref());

        // Expand a data encryption key and a data authentication key from the transcript.
        let (mut dek, mut dak) = ([0u8; 32], [0u8; 32]);
        self.expand("data encryption key", &mut dek);
        self.expand("data authentication key", &mut dak);

        // Calculate an AES-256-GMAC authenticator of the plaintext.
        let auth = aes_gmac(&dak, in_out);

        // Append the authenticator to the transcript.
        let _ = self.transcript.update(&auth);

        // Expand an authentication tag.
        self.expand("authentication tag", tag);

        // Encrypt the plaintext using AES-256-CTR with the tag as the IV.
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
        let _ = self.transcript.update(&[OpCode::AuthCrypt as u8]);
        let _ = self.transcript.update(left_encode(label.len() as u64 * 8).as_ref());
        let _ = self.transcript.update(label.as_bytes());
        let _ = self.transcript.update(left_encode(in_out.len() as u64 * 8).as_ref());

        // Expand a data encryption key and a data authentication key from the transcript.
        let (mut dek, mut dak) = ([0u8; 32], [0u8; 32]);
        self.expand("data encryption key", &mut dek);
        self.expand("data authentication key", &mut dak);

        // Decrypt the ciphertext using AES-256-CTR with the tag as the IV.
        aes_ctr(&dek, tag, in_out);

        // Calculate an AES-256-GMAC authenticator of the plaintext.
        let auth = aes_gmac(&dak, in_out);

        // Append the authenticator to the transcript.
        let _ = self.transcript.update(&auth);

        // Expand a counterfactual authentication tag.
        let mut tag_p = [0u8; TAG_LEN];
        self.expand("authentication tag", &mut tag_p);

        // Ratchet the transcript.
        self.ratchet();

        // Compare the tag and the counterfactual tag in constant time.
        if memcmp::eq(tag, &tag_p) {
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
        // Expand a ratchet key.
        let mut rak = [0u8; 32];
        self.expand("ratchet key", &mut rak);

        // Clear the transcript.
        self.transcript = Hasher::new(MessageDigest::sha512()).expect("should implement SHA-512");

        // Append the operation metadata and data to the transcript.
        let _ = self.transcript.update(&[OpCode::Ratchet as u8]);
        let _ = self.transcript.update(left_encode(rak.len() as u64 * 8).as_ref());
        let _ = self.transcript.update(&rak);
    }

    /// Clones the protocol's transcript, appends an expand operation code, the label length, the
    /// label, and the requested output length, and returns n (<=32) bytes of derived output.
    fn expand(&self, label: &str, out: &mut [u8]) {
        debug_assert!(out.len() <= 32, "expand output must be <=32 bytes");

        // Create a copy of the transcript.
        let mut clone = self.transcript.clone();

        // Append the operation metadata and data to the transcript copy.
        let _ = clone.update(&[OpCode::Expand as u8]);
        let _ = clone.update(left_encode(label.len() as u64 * 8).as_ref());
        let _ = clone.update(label.as_bytes());
        let _ = clone.update(right_encode(out.len() as u64 * 8).as_ref());

        // Generate up to 32 bytes of output.
        let h = clone.finish().expect("should finish");
        out.copy_from_slice(&h[..out.len()]);
    }
}

impl Debug for Protocol {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Protocol").finish_non_exhaustive()
    }
}

/// All Lockstitch operation types.
#[derive(Debug, Clone, Copy)]
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
fn left_encode(mut value: u64) -> EncodedLen {
    let mut b = [0u8; 9];
    let n = 8 - ((value | 1).leading_zeros() / 8) as usize;
    value <<= (8 - n) * 8;
    b[1..].copy_from_slice(&value.to_be_bytes());
    b[0] = n as u8;
    EncodedLen { b, n: (n + 1) }
}

/// Encodes a value using [NIST SP 800-185]'s `right_encode`.
///
/// [NIST SP 800-185]: https://www.nist.gov/publications/sha-3-derived-functions-cshake-kmac-tuplehash-and-parallelhash
fn right_encode(mut value: u64) -> EncodedLen {
    let mut b = [0u8; 9];
    let n = 8 - ((value | 1).leading_zeros() / 8) as usize;
    value <<= (8 - n) * 8;
    b[..8].copy_from_slice(&value.to_be_bytes());
    b[n] = n as u8;
    EncodedLen { b, n: (n + 1) }
}

/// A length encoded with either [left_encode] or [right_encode].
struct EncodedLen {
    b: [u8; 9],
    n: usize,
}

impl AsRef<[u8]> for EncodedLen {
    fn as_ref(&self) -> &[u8] {
        &self.b[..self.n]
    }
}

/// Encrypts (or decrypts) an input with AES-256-CTR.
fn aes_ctr(key: &[u8], nonce: &[u8], in_out: &mut [u8]) {
    let mut ctx = CipherCtx::new().expect("should create a cipher context");
    ctx.encrypt_init(Some(Cipher::aes_256_ctr()), Some(key), Some(nonce))
        .expect("should be a valid AES-256-CTR key and nonce");
    ctx.cipher_update_inplace(in_out, in_out.len()).expect("should perform AES-256-CTR");
}

/// Calculates an AES-256-GMAC authenticator of the input.
fn aes_gmac(key: &[u8], input: &[u8]) -> [u8; 16] {
    let mut ctx = CipherCtx::new().expect("should create a cipher context");
    ctx.encrypt_init(Some(Cipher::aes_256_gcm()), Some(key), Some(&[0u8; 12]))
        .expect("should be a valid AES-256-GCM key and nonce");
    ctx.cipher_update(input, None).expect("should process authenticated data");
    ctx.cipher_final(&mut []).expect("should finalize GCM context");
    let mut tag = [0u8; 16];
    ctx.tag(&mut tag).expect("should calculate authenticator");
    tag
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

        expect!["49639b877ddea480"].assert_eq(&hex::encode(protocol.derive_array::<8>("third")));

        let mut plaintext = b"this is an example".to_vec();
        protocol.encrypt("fourth", &mut plaintext);
        expect!["34830931d97c14b4b4a5dd2093429347aeb6"].assert_eq(&hex::encode(plaintext));

        let plaintext = b"this is an example";
        let mut sealed = vec![0u8; plaintext.len() + TAG_LEN];
        sealed[..plaintext.len()].copy_from_slice(plaintext);
        protocol.seal("fifth", &mut sealed);

        expect!["76bef04c2d274072f84e52867c347783aa489041b8936ca27e0f30b5181f1def3879"]
            .assert_eq(&hex::encode(sealed));

        expect!["d95ee73d86687616"].assert_eq(&hex::encode(protocol.derive_array::<8>("sixth")));
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
            a_e.extend_from_slice(left_encode(a.len() as u64 * 8).as_ref());
            a_e.extend_from_slice(&a);

            let mut b_e = Vec::new();
            b_e.extend_from_slice(left_encode(b.len() as u64 * 8).as_ref());
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
            let a_e = left_encode(a);
            let b_e = left_encode(b);

            if a == b {
                assert_eq!(a_e.as_ref(), b_e.as_ref());
            } else {
                assert_ne!(a_e.as_ref(), b_e.as_ref());
            }
        });
    }

    #[test]
    fn left_encode_test_vectors() {
        assert_eq!(left_encode(0).as_ref(), [1, 0]);

        assert_eq!(left_encode(128).as_ref(), [1, 128]);

        assert_eq!(left_encode(65536).as_ref(), [3, 1, 0, 0]);

        assert_eq!(left_encode(4096).as_ref(), [2, 16, 0]);

        assert_eq!(
            left_encode(18446744073709551615).as_ref(),
            [8, 255, 255, 255, 255, 255, 255, 255, 255]
        );

        assert_eq!(left_encode(12345).as_ref(), [2, 48, 57]);
    }

    #[test]
    fn right_encode_test_vectors() {
        assert_eq!(right_encode(0).as_ref(), [0, 1]);

        assert_eq!(right_encode(128).as_ref(), [128, 1]);

        assert_eq!(right_encode(65536).as_ref(), [1, 0, 0, 3]);

        assert_eq!(right_encode(4096).as_ref(), [16, 0, 2]);

        assert_eq!(
            right_encode(18446744073709551615).as_ref(),
            [255, 255, 255, 255, 255, 255, 255, 255, 8]
        );

        assert_eq!(right_encode(12345).as_ref(), [48, 57, 2]);
    }
}
