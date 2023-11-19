#![cfg_attr(not(feature = "std"), no_std)]
#![doc = include_str!("../README.md")]
#![warn(missing_docs)]

use core::fmt::Debug;

use crate::aegis_128l::Aegis128L;

use cmov::CmovEq;
use sha2::digest::Digest;
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
#[derive(Debug, Clone)]
pub struct Protocol {
    transcript: Sha256,
}

impl Protocol {
    /// Create a new protocol with the given domain.
    #[inline]
    pub fn new(domain: &str) -> Protocol {
        // Initialize a protocol with an empty transcript.
        let mut protocol = Protocol { transcript: Sha256::new() };

        // Append the Init op header to the transcript with the domain as the label.
        //
        //   0x01 || left_encode(|domain|) || domain
        protocol.op_header(OpCode::Init, domain.as_bytes());

        protocol
    }

    /// Mixes the given label and slice into the protocol state.
    #[inline]
    pub fn mix(&mut self, label: &[u8], input: &[u8]) {
        // Append a Mix op header with the label to the transcript.
        //
        //   0x02 || left_encode(|label|) || label
        self.op_header(OpCode::Mix, label);

        // Append the input to the transcript with right-encoded length.
        //
        //   input || right_encode(|input|)
        self.transcript.update(input);
        self.transcript.update(right_encode(
            &mut [0u8; 9],
            (input.len() as u64).checked_mul(8).expect("should be <= 2^61 bits"),
        ));
    }

    /// Moves the protocol into a [`Write`] implementation, mixing all written data in a single
    /// operation and passing all writes to `inner`. Use [`MixWriter::into_inner`] to finish the
    /// operation and recover the protocol and `inner`.
    #[inline]
    #[cfg(feature = "std")]
    pub fn mix_writer<W: std::io::Write>(mut self, label: &[u8], inner: W) -> MixWriter<W> {
        // Append a Mix op header with the label to the transcript.
        self.op_header(OpCode::Mix, label);

        // Move the protocol to a MixWriter.
        MixWriter { protocol: self, inner, len: 0 }
    }

    /// Derive output from the protocol's current state and fill the given slice with it.
    #[inline]
    pub fn derive(&mut self, label: &[u8], out: &mut [u8]) {
        const MAX_LEN: u64 = (u32::MAX - 1) as u64 * 32;
        assert!((out.len() as u64) < MAX_LEN, "derive is limited to output lengths <= {}", MAX_LEN);

        // Append a Derive op header with the label to the transcript.
        //
        //   0x03 || left_encode(|label|) || label
        self.op_header(OpCode::Derive, label);

        // Calculate the hash of the transcript and replace it with an empty transcript.
        let ikm = self.transcript.finalize_reset();

        // Use Concat-KDF to derive a new KDF key and any additional output.
        let mut kdf_key = [0u8; 32];
        concat_kdf(&ikm, &mut kdf_key, out);

        // Perform a Mix operation with the KDF key.
        self.mix(b"kdf-key", &kdf_key);

        // Perform a Mix operation with the output length.
        self.mix(b"len", left_encode(&mut [0u8; 9], out.len() as u64 * 8));
    }

    /// Derive output from the protocol's current state and return it as an `N`-byte array.
    #[inline]
    pub fn derive_array<const N: usize>(&mut self, label: &[u8]) -> [u8; N] {
        let mut out = [0u8; N];
        self.derive(label, &mut out);
        out
    }

    /// Encrypt the given slice in place.
    #[inline]
    pub fn encrypt(&mut self, label: &[u8], in_out: &mut [u8]) {
        // Append a Crypt op header with the label to the transcript.
        //
        //   0x04 || left_encode(|label|) || label
        self.op_header(OpCode::Crypt, label);

        // Derive an AEGIS-128L key and nonce.
        let kn = self.derive_array::<32>(b"key");
        let (k, n) = kn.split_at(16);
        let mut aegis = Aegis128L::new(
            k.try_into().expect("should be 16 bytes"),
            n.try_into().expect("should be 16 bytes"),
        );

        // Encrypt the plaintext.
        aegis.encrypt(in_out);

        // Perform a Mix operation with the AEGIS-128L tag.
        self.mix(b"tag", &aegis.finalize());
    }

    /// Decrypt the given slice in place.
    #[inline]
    pub fn decrypt(&mut self, label: &[u8], in_out: &mut [u8]) {
        // Append a Crypt op header with the label to the transcript.
        //
        //   0x04 || left_encode(|label|) || label
        self.op_header(OpCode::Crypt, label);

        // Derive an AEGIS-128L key and nonce.
        let kn = self.derive_array::<32>(b"key");
        let (k, n) = kn.split_at(16);
        let mut aegis = Aegis128L::new(
            k.try_into().expect("should be 16 bytes"),
            n.try_into().expect("should be 16 bytes"),
        );

        // Decrypt the ciphertext.
        aegis.decrypt(in_out);

        // Perform a Mix operation with the AEGIS-128L tag.
        self.mix(b"tag", &aegis.finalize());
    }

    /// Seals the given mutable slice in place.
    ///
    /// The last [`TAG_LEN`] bytes of the slice will be overwritten with the authentication tag.
    #[inline]
    pub fn seal(&mut self, label: &[u8], in_out: &mut [u8]) {
        // Split the buffer into plaintext and tag.
        let (in_out, tag) = in_out.split_at_mut(in_out.len() - TAG_LEN);

        // Append an AuthCrypt op header with the label to the transcript.
        //
        //   0x05 || left_encode(|label|) || label
        self.op_header(OpCode::AuthCrypt, label);

        // Perform a Crypt operation with the plaintext.
        self.encrypt(b"message", in_out);

        // Perform a Derive operation to produce an authentication tag.
        self.derive(b"tag", tag);
    }

    /// Opens the given mutable slice in place. Returns the plaintext slice of `in_out` if the input
    /// was authenticated. The last [`TAG_LEN`] bytes of the slice will be unmodified.
    #[inline]
    #[must_use]
    pub fn open<'a>(&mut self, label: &[u8], in_out: &'a mut [u8]) -> Option<&'a [u8]> {
        // Split the buffer into ciphertext and tag.
        let (in_out, tag) = in_out.split_at_mut(in_out.len() - TAG_LEN);

        // Append an AuthCrypt op header with the label to the transcript.
        //
        //   0x05 || left_encode(|label|) || label
        self.op_header(OpCode::AuthCrypt, label);

        // Perform a Crypt operation with the ciphertext.
        self.decrypt(b"message", in_out);

        // Perform a Derive operation to produce a counterfactual authentication tag.
        let tag_p = self.derive_array::<TAG_LEN>(b"tag");

        // Check the tag against the counterfactual tag in constant time.
        if ct_eq(tag, &tag_p) {
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

    /// Clones the protocol and mixes `secrets` plus 64 random bytes into the clone. Passes the
    /// clone to `f` and if `f` returns `Some(R)`, returns `R`. Iterates until a value is returned.
    #[cfg(feature = "hedge")]
    #[must_use]
    pub fn hedge<R>(
        &self,
        mut rng: impl rand_core::RngCore + rand_core::CryptoRng,
        secrets: &[impl AsRef<[u8]>],
        f: impl Fn(&mut Self) -> Option<R>,
    ) -> R {
        for _ in 0..10_000 {
            // Clone the protocol's state.
            let mut clone = self.clone();

            // Mix each secret into the clone.
            for s in secrets {
                clone.mix(b"secret", s.as_ref());
            }

            // Mix a random value into the clone.
            let mut r = [0u8; 64];
            rng.fill_bytes(&mut r);
            clone.mix(b"nonce", &r);

            // Call the given function with the clone and return if the function was successful.
            if let Some(r) = f(&mut clone) {
                return r;
            }
        }

        unreachable!("unable to hedge a valid value in 10,000 tries");
    }

    /// Append an operation header with an optional label to the protocol transcript.
    #[inline]
    fn op_header(&mut self, op_code: OpCode, label: &[u8]) {
        // Append the operation code and label to the transcript:
        //
        //   op_code || left_encode(|label|) || label
        self.transcript.update([op_code as u8]);
        self.transcript.update(left_encode(&mut [0u8; 9], label.len() as u64 * 8));
        self.transcript.update(label);
    }
}

/// Compare two slices for equality in constant time.
#[inline]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    let mut res = 1;
    a.cmovne(b, 0, &mut res);
    res != 0
}

/// Derive a KDF key and additional output from [NIST SP 800-56C Rev. 2][]'s  _One-Step Key
/// Derivation_ with SHA-256.
///
/// [NIST SP 800-56C Rev. 2]: https://csrc.nist.gov/pubs/sp/800/56/c/r2/final
fn concat_kdf(ikm: &[u8], kdf_key: &mut [u8; 32], out: &mut [u8]) {
    let mut counter = 1u32;
    let mut kdf = Sha256::new();

    // Directly use the first full block of KDF output as the KDF key,
    kdf.update(counter.to_be_bytes());
    kdf.update(ikm);
    kdf.update(b"lockstitch");
    kdf.finalize_into_reset(kdf_key.into());

    // Process all full-sized blocks of output to eliminate bounds checks.
    let mut chunks = out.chunks_exact_mut(32);
    for chunk in chunks.by_ref() {
        counter += 1;
        kdf.update(counter.to_be_bytes());
        kdf.update(ikm);
        kdf.update(b"lockstitch");
        kdf.finalize_into_reset(chunk.into());
    }

    // Process the remainder, if necessary.
    let remainder = chunks.into_remainder();
    if !remainder.is_empty() {
        counter += 1;
        kdf.update(counter.to_be_bytes());
        kdf.update(ikm);
        kdf.update(b"lockstitch");
        remainder.copy_from_slice(&kdf.finalize_reset()[..remainder.len()]);
    }
}

/// All Lockstitch operation types.
#[derive(Debug, Clone, Copy)]
enum OpCode {
    Init = 0x01,
    Mix = 0x02,
    Derive = 0x03,
    Crypt = 0x04,
    AuthCrypt = 0x05,
}

/// A [`Write`] implementation which combines all written data into a single `Mix` operation and
/// passes all writes to an inner writer.
#[cfg(feature = "std")]
#[derive(Debug)]
pub struct MixWriter<W> {
    protocol: Protocol,
    inner: W,
    len: u64,
}

#[cfg(feature = "std")]
impl<W: std::io::Write> MixWriter<W> {
    /// Finishes the `Mix` operation and returns the inner [`Protocol`] and writer.
    #[inline]
    pub fn into_inner(mut self) -> (Protocol, W) {
        // Append the right-encoded length to the transcript.
        self.protocol.transcript.update(right_encode(
            &mut [0u8; 9],
            self.len.checked_mul(8).expect("should be <= 2^61 bits"),
        ));
        (self.protocol, self.inner)
    }
}

#[cfg(feature = "std")]
impl<W: std::io::Write> std::io::Write for MixWriter<W> {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // Track the written length.
        self.len += u64::try_from(buf.len()).expect("usize should be <= u64");
        // Append the written slice to the protocol transcript.
        self.protocol.transcript.update(buf);
        // Pass the slice to the inner writer and return the result.
        self.inner.write(buf)
    }

    #[inline]
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Encode a value using [NIST SP 800-185][]'s `left_encode`.
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

/// Encode a value using [NIST SP 800-185][]'s `right_encode`.
///
/// [NIST SP 800-185]: https://www.nist.gov/publications/sha-3-derived-functions-cshake-kmac-tuplehash-and-parallelhash
#[inline]
fn right_encode(buf: &mut [u8; 9], value: u64) -> &[u8] {
    let len = buf.len();
    buf[..len - 1].copy_from_slice(&value.to_be_bytes());
    let n = (len - 1 - value.leading_zeros() as usize / 8).max(1);
    buf[len - 1] = n as u8;
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
        protocol.mix(b"first", b"one");
        protocol.mix(b"second", b"two");

        expect!["75d890340e76facd"].assert_eq(&hex::encode(protocol.derive_array::<8>(b"third")));

        let mut plaintext = b"this is an example".to_vec();
        protocol.encrypt(b"fourth", &mut plaintext);
        expect!["98c34aba949134ead021cbc12596e7c29827"].assert_eq(&hex::encode(plaintext));

        let plaintext = b"this is an example";
        let mut sealed = vec![0u8; plaintext.len() + TAG_LEN];
        sealed[..plaintext.len()].copy_from_slice(plaintext);
        protocol.seal(b"fifth", &mut sealed);

        expect!["a4f5cebc56e71efc883365751fa99043d21f025bc2f66afb0fd22129908d51614449"]
            .assert_eq(&hex::encode(sealed));

        expect!["82643fff7a7bb02e"].assert_eq(&hex::encode(protocol.derive_array::<8>(b"sixth")));
    }

    #[test]
    fn readers() {
        let mut slices = Protocol::new("com.example.streams");
        slices.mix(b"first", b"one");
        slices.mix(b"second", b"two");

        let streams = Protocol::new("com.example.streams");
        let mut streams_write = streams.mix_writer(b"first", io::sink());
        io::copy(&mut Cursor::new(b"one"), &mut streams_write)
            .expect("cursor reads and sink writes should be infallible");
        let (streams, _) = streams_write.into_inner();

        let mut output = Vec::new();
        let mut streams_write = streams.mix_writer(b"second", &mut output);
        io::copy(&mut Cursor::new(b"two"), &mut streams_write)
            .expect("cursor reads and sink writes should be infallible");
        let (mut streams, output) = streams_write.into_inner();

        assert_eq!(slices.derive_array::<16>(b"third"), streams.derive_array::<16>(b"third"));
        assert_eq!(b"two".as_slice(), output);
    }

    #[test]
    #[cfg(feature = "hedge")]
    fn hedging() {
        let mut hedger = Protocol::new("com.example.hedge");
        hedger.mix(b"first", b"one");
        let tag = hedger.hedge(rand::thread_rng(), &[b"two"], |clone| {
            let tag = clone.derive_array::<16>(b"tag");
            (tag[0] == 0).then_some(tag)
        });

        assert_eq!(tag[0], 0);
    }

    #[test]
    fn edge_case() {
        let mut sender = Protocol::new("");
        let mut message = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        sender.encrypt(b"message", &mut message);
        let tag_s = sender.derive_array::<TAG_LEN>(b"tag");

        let mut receiver = Protocol::new("");
        receiver.decrypt(b"message", &mut message);
        let tag_r = receiver.derive_array::<TAG_LEN>(b"tag");

        assert_eq!(message, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(tag_s, tag_r);
    }

    #[test]
    fn test_left_encode() {
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
    fn test_right_encode() {
        let mut buf = [0; 9];

        assert_eq!(right_encode(&mut buf, 0), [0, 1]);

        assert_eq!(right_encode(&mut buf, 128), [128, 1]);

        assert_eq!(right_encode(&mut buf, 65536), [1, 0, 0, 3]);

        assert_eq!(right_encode(&mut buf, 4096), [16, 0, 2]);

        assert_eq!(
            right_encode(&mut buf, 18446744073709551615),
            [255, 255, 255, 255, 255, 255, 255, 255, 8]
        );

        assert_eq!(right_encode(&mut buf, 12345), [48, 57, 2]);
    }
}
