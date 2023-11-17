#![cfg_attr(not(feature = "std"), no_std)]
#![doc = include_str!("../README.md")]
#![warn(missing_docs)]

use core::fmt::Debug;

use crate::aegis_128l::Aegis128L;

use cmov::CmovEq;
use concat_kdf::derive_key_into;
use sha2::digest::{Digest, FixedOutputReset};
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

        // Append the Init op header to the transcript.
        protocol.op_header(OpCode::Init, None);

        // Perform a Mix operation with the domain.
        protocol.mix(b"domain", domain.as_bytes());

        protocol
    }

    /// Mixes the given label and slice into the protocol state.
    #[inline]
    pub fn mix(&mut self, label: &[u8], input: &[u8]) {
        // Append a Mix op header with the label to the transcript.
        self.op_header(OpCode::Mix, Some(label));

        // Append the input to the transcript with right-encoded length.
        //
        // input || right_encode(|input|)
        self.transcript.update(input);
        self.transcript.update(right_encode(&mut [0u8; 17], input.len() as u128 * 8));
    }

    /// Moves the protocol into a [`Write`] implementation, mixing all written data in a single
    /// operation and passing all writes to `inner`. Use [`MixWriter::into_inner`] to finish the
    /// operation and recover the protocol and `inner`.
    #[cfg(feature = "std")]
    pub fn mix_writer<W: std::io::Write>(mut self, label: &[u8], inner: W) -> MixWriter<W> {
        // Append a Mix op header with the label to the transcript.
        self.op_header(OpCode::Mix, Some(label));

        // Move the protocol to a MixWriter.
        MixWriter { protocol: self, inner, len: 0 }
    }

    /// Modifies the protocol's state irreversibly, preventing rollback.
    pub fn ratchet(&mut self) {
        // Perform a Ratchet operation, ignoring the key and nonce.
        let _ = self.ratchet_with_output();
    }

    /// Derive output from the protocol's current state and fill the given slice with it.
    #[inline]
    pub fn derive(&mut self, label: &[u8], out: &mut [u8]) {
        // Append a Derive op header with the label to the transcript.
        self.op_header(OpCode::Derive, Some(label));

        // Perform a Ratchet operation.
        let (k, n) = self.ratchet_with_output();
        let mut aegis = Aegis128L::new(&k, &n);

        // Generate N bytes of PRF output.
        aegis.prf(out);

        // Perform a Mix operation with the output length.
        self.mix(b"len", left_encode(&mut [0u8; 17], out.len() as u128 * 8));
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
        self.op_header(OpCode::Crypt, Some(label));

        // Perform a Ratchet operation.
        let (k, n) = self.ratchet_with_output();
        let mut aegis = Aegis128L::new(&k, &n);

        // Encrypt the plaintext.
        aegis.encrypt(in_out);

        // Perform a Mix operation with the AEGIS-128L tag.
        self.mix(b"tag", &aegis.finalize());
    }

    /// Decrypt the given slice in place.
    #[inline]
    pub fn decrypt(&mut self, label: &[u8], in_out: &mut [u8]) {
        // Append a Crypt op header with the label to the transcript.
        self.op_header(OpCode::Crypt, Some(label));

        // Perform a Ratchet operation.
        let (k, n) = self.ratchet_with_output();
        let mut aegis = Aegis128L::new(&k, &n);

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
        self.op_header(OpCode::AuthCrypt, Some(label));

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
        self.op_header(OpCode::AuthCrypt, Some(label));

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

    /// Perform a `Ratchet` operation, returning an AEGIS-128L instance for optional output.
    #[inline]
    #[must_use]
    fn ratchet_with_output(&mut self) -> ([u8; 16], [u8; 16]) {
        // Append a  Ratchet op header to the transcript.
        self.op_header(OpCode::Ratchet, None);

        // Calculate the hash of the transcript and replace it with an empty transcript.
        let ikm = self.transcript.finalize_fixed_reset();

        // Use Concat-KDF with SHA-256 to derive 64 bytes of new key material.
        let mut kdf_out = [0u8; 64];
        derive_key_into::<Sha256>(&ikm, b"lockstitch", &mut kdf_out).expect("should derive keys");

        // Split the KDF output into a 32-byte KDF key, a 16-byte output key, and a 16-byte output
        // nonce.
        let (kdf_key, output_key) = kdf_out.split_at(32);
        let (output_key, output_nonce) = output_key.split_at(16);

        // Perform a Mix operation with the KDF key.
        self.mix(b"kdf-key", kdf_key);

        // Return the key and nonce for optional use.
        (
            output_key.try_into().expect("should be valid AEGIS-128L key"),
            output_nonce.try_into().expect("should be valid AEGIS-128L nonce"),
        )
    }

    /// Append an operation header with an optional label to the protocol transcript.
    #[inline]
    fn op_header(&mut self, op_code: OpCode, label: Option<&[u8]>) {
        // Append the operation code to the transcript:
        //
        //   op_code
        self.transcript.update([op_code as u8]);

        // Append the label, if any, to the transcript:
        //
        //   left_encode(|label|) || label
        if let Some(label) = label {
            self.transcript.update(left_encode(&mut [0u8; 17], label.len() as u128 * 8));
            self.transcript.update(label);
        }
    }
}

/// Encode a value using [NIST SP 800-185][]'s `left_encode`.
///
/// [NIST SP 800-185]: https://www.nist.gov/publications/sha-3-derived-functions-cshake-kmac-tuplehash-and-parallelhash
#[inline]
fn left_encode(buf: &mut [u8; 17], value: u128) -> &[u8] {
    buf[1..].copy_from_slice(&value.to_be_bytes());
    let offset = buf.iter().position(|&v| v != 0).unwrap_or(8);
    buf[offset - 1] = (17 - offset) as u8;
    &buf[offset - 1..]
}

/// Encode a value using [NIST SP 800-185][]'s `left_encode`.
///
/// [NIST SP 800-185]: https://www.nist.gov/publications/sha-3-derived-functions-cshake-kmac-tuplehash-and-parallelhash
#[inline]
fn right_encode(buf: &mut [u8; 17], value: u128) -> &[u8] {
    buf[..16].copy_from_slice(&value.to_be_bytes());
    let offset = buf.iter().position(|&v| v != 0).unwrap_or(7);
    buf[16] = (16 - offset) as u8;
    &buf[offset..]
}

/// Compare two slices for equality in constant time.
#[inline]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    let mut res = 1;
    a.cmovne(b, 0, &mut res);
    res != 0
}

/// All Lockstitch operation types.
#[derive(Debug, Clone, Copy)]
enum OpCode {
    Mix = 0x01,
    Init = 0x02,
    Ratchet = 0x03,
    Derive = 0x04,
    Crypt = 0x05,
    AuthCrypt = 0x06,
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
        self.protocol.transcript.update(right_encode(&mut [0u8; 17], self.len as u128 * 8));
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

        expect!["a80e8d73cb0513f7"].assert_eq(&hex::encode(protocol.derive_array::<8>(b"third")));

        let mut plaintext = b"this is an example".to_vec();
        protocol.encrypt(b"fourth", &mut plaintext);
        expect!["15e4c57d88aca21416cdcbdcde960bdd3b7d"].assert_eq(&hex::encode(plaintext));

        protocol.ratchet();

        let plaintext = b"this is an example";
        let mut sealed = vec![0u8; plaintext.len() + TAG_LEN];
        sealed[..plaintext.len()].copy_from_slice(plaintext);
        protocol.seal(b"fifth", &mut sealed);

        expect!["575b7095719784405a1c97df48cf97730e82588427f1a908f02bb2711e55cdd289e8"]
            .assert_eq(&hex::encode(sealed));

        expect!["c286877e68890b53"].assert_eq(&hex::encode(protocol.derive_array::<8>(b"sixth")));
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
}
