#![cfg_attr(not(feature = "std"), no_std)]
#![doc = include_str!("../README.md")]
#![warn(
    missing_docs,
    rust_2018_idioms,
    trivial_casts,
    unused_lifetimes,
    unused_qualifications,
    missing_debug_implementations,
    clippy::cognitive_complexity,
    clippy::missing_const_for_fn,
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::semicolon_if_nothing_returned
)]

use core::fmt::Debug;
#[cfg(feature = "std")]
use std::io::{self, Write};

use aegis_128l::Aegis128L;
use cmov::CmovEq;
#[cfg(feature = "hedge")]
use rand_core::{CryptoRng, RngCore};
use sha2::digest::{Digest, FixedOutputReset};
use sha2::Sha256;

mod aegis_128l;

#[cfg(feature = "docs")]
#[doc = include_str!("../design.md")]
pub mod design {}

#[cfg(feature = "docs")]
#[doc = include_str!("../perf.md")]
pub mod perf {}

mod integration_tests;

/// The length of an authentication tag in bytes.
pub const TAG_LEN: usize = 16;

/// A stateful object providing fine-grained symmetric-key cryptographic services like hashing,
/// message authentication codes, pseudo-random functions, authenticated encryption, and more.
#[derive(Debug, Clone)]
pub struct Protocol {
    state: Sha256,
}

impl Protocol {
    /// Create a new protocol with the given domain.
    #[inline]
    pub fn new(domain: &'static str) -> Protocol {
        // Create a protocol with a fresh SHA-256 instance.
        let mut protocol = Protocol { state: Sha256::new() };

        // Update the protocol with the domain and the INIT operation.
        protocol.process(domain.as_bytes(), Operation::Init);

        protocol
    }

    /// Mixes the given slice into the protocol state.
    #[inline]
    pub fn mix(&mut self, data: &[u8]) {
        // Update the state with the data and operation code.
        self.process(data, Operation::Mix);
    }

    /// Moves the protocol into a [`Write`] implementation, mixing all written data in a single
    /// operation and passing all writes to `inner`. Use [`MixWriter::into_inner`] to finish the
    /// operation and recover the protocol and `inner`.
    #[cfg(feature = "std")]
    pub const fn mix_writer<W: Write>(self, inner: W) -> MixWriter<W> {
        MixWriter { state: self.state, inner, total: 0 }
    }

    /// Derive output from the protocol's current state and fill the given slice with it.
    #[inline]
    pub fn derive(&mut self, out: &mut [u8]) {
        // Chain the protocol's state and key an AEGIS-128L instance for output.
        let mut aegis = self.chain(Operation::Derive);

        // Fill the buffer with PRF output.
        aegis.prf(out);

        // Update the state with the output length and the operation code.
        self.process(&(out.len() as u64).to_le_bytes(), Operation::Derive);
    }

    /// Derive output from the protocol's current state and return it as an `N`-byte array.
    #[inline]
    pub fn derive_array<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        self.derive(&mut out);
        out
    }

    /// Encrypt the given slice in place.
    #[inline]
    pub fn encrypt(&mut self, in_out: &mut [u8]) {
        // Chain the protocol's state and key an AEGIS-128L instance for output.
        let mut aegis = self.chain(Operation::Crypt);

        // Encrypt the plaintext.
        aegis.encrypt(in_out);

        // Update the state with the long tag and the operation code.
        self.process(&aegis.finalize(), Operation::Crypt);
    }

    /// Decrypt the given slice in place.
    #[inline]
    pub fn decrypt(&mut self, in_out: &mut [u8]) {
        // Chain the protocol's state and key an AEGIS-128L instance for output.
        let mut aegis = self.chain(Operation::Crypt);

        // Decrypt the ciphertext.
        aegis.decrypt(in_out);

        // Update the state with the long tag and the operation code.
        self.process(&aegis.finalize(), Operation::Crypt);
    }

    /// Seals the given mutable slice in place.
    ///
    /// The last [`TAG_LEN`] bytes of the slice will be overwritten with the authentication tag.
    #[inline]
    pub fn seal(&mut self, in_out: &mut [u8]) {
        // Split the buffer into plaintext and tag.
        let (in_out, tag) = in_out.split_at_mut(in_out.len() - TAG_LEN);

        // Encrypt the plaintext.
        self.encrypt(in_out);

        // Derive a tag.
        self.derive(tag);
    }

    /// Opens the given mutable slice in place. Returns the plaintext slice of `in_out` if the input
    /// was authenticated. The last [`TAG_LEN`] bytes of the slice will be unmodified.
    #[inline]
    #[must_use]
    pub fn open<'a>(&mut self, in_out: &'a mut [u8]) -> Option<&'a [u8]> {
        // Split the buffer into ciphertext and tag.
        let (in_out, tag) = in_out.split_at_mut(in_out.len() - TAG_LEN);

        // Decrypt the plaintext.
        self.decrypt(in_out);

        // Derive a counterfactual tag.
        let tag_p = self.derive_array::<TAG_LEN>();

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

    /// Modifies the protocol's state irreversibly, preventing rollback.
    pub fn ratchet(&mut self) {
        // Chain the protocol's key, ignoring the PRF output.
        let _ = self.chain(Operation::Ratchet);

        // Update the state with the operation code and zero length.
        self.end_op(Operation::Ratchet, 0);
    }

    /// Clones the protocol and mixes `secrets` plus 64 random bytes into the clone. Passes the
    /// clone to `f` and if `f` returns `Some(R)`, returns `R`. Iterates until a value is returned.
    #[cfg(feature = "hedge")]
    #[must_use]
    pub fn hedge<R>(
        &self,
        mut rng: impl RngCore + CryptoRng,
        secrets: &[impl AsRef<[u8]>],
        f: impl Fn(&mut Self) -> Option<R>,
    ) -> R {
        for _ in 0..10_000 {
            // Clone the protocol's state.
            let mut clone = self.clone();

            // Mix each secret into the clone.
            for s in secrets {
                clone.mix(s.as_ref());
            }

            // Mix a random value into the clone.
            let mut r = [0u8; 64];
            rng.fill_bytes(&mut r);
            clone.mix(&r);

            // Call the given function with the clone and return if the function was successful.
            if let Some(r) = f(&mut clone) {
                return r;
            }
        }

        unreachable!("unable to hedge a valid value in 10,000 tries");
    }

    /// Replace the protocol's state with derived output and return an AEGIS-128L instance for
    /// output.
    #[inline]
    #[must_use]
    fn chain(&mut self, operation: Operation) -> Aegis128L {
        // Finalize the current state and reset it to an uninitialized state.
        let hash = self.state.finalize_fixed_reset();

        // Split the hash into a key and nonce and initialize an AEGIS-128L instance for PRF output.
        let (prf_key, prf_nonce) = hash.split_at(16);
        let mut prf = Aegis128L::new(
            &prf_key.try_into().expect("should be valid AEGIS-128L key"),
            &prf_nonce.try_into().expect("should be valid AEGIS-128L nonce"),
        );

        // Generate 64 bytes of PRF output.
        let mut prf_out = [0u8; 64];
        prf.prf(&mut prf_out);

        // Split the PRF output into a 32-byte chain key, a 16-byte output key, and a 16-byte output
        // nonce, setting the first bytes of the output nonce to the operation code.
        let (chain_key, output_key) = prf_out.split_at_mut(32);
        let (output_key, output_nonce) = output_key.split_at_mut(16);
        output_nonce[0] = operation as u8;

        // Initialize the current state with the chain key.
        self.process(chain_key, Operation::Chain);

        // Initialize an AEGIS-128L instance for output.
        Aegis128L::new(
            &output_key.try_into().expect("should be valid AEGIS-128L key"),
            &output_nonce.try_into().expect("should be valid AEGIS-128L nonce"),
        )
    }

    /// Process a single piece of input for an operation.
    #[inline]
    fn process(&mut self, input: &[u8], operation: Operation) {
        // Update the state with the input.
        self.state.update(input);

        // End the operation with the operation code and input length.
        self.end_op(operation, input.len() as u64);
    }

    /// End an operation, including the number of bytes processed.
    #[inline]
    fn end_op(&mut self, operation: Operation, n: u64) {
        // Allocate a buffer for output.
        let mut buffer = [0u8; 10];
        let (re_x, re_n) = buffer.split_at_mut(8);
        let (re_n, op) = re_n.split_at_mut(1);

        // Encode the number of bytes processed using NIST SP-800-185's right_encode.
        re_x.copy_from_slice(&n.to_be_bytes());
        let offset = re_x.iter().position(|i| *i != 0).unwrap_or(7);
        re_n[0] = 8 - offset as u8;

        // Set the last byte to the operation code.
        op[0] = operation as u8;

        // Update the state with the length and operation code.
        self.state.update(&buffer[offset..]);
    }
}

/// Compare two slices for equality in constant time.
#[inline]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    let mut res = 1;
    a.cmovne(b, 0, &mut res);
    res != 0
}

/// A primitive operation in a protocol with a unique 1-byte code.
#[derive(Debug, Clone, Copy)]
enum Operation {
    Init = 0x01,
    Mix = 0x02,
    Derive = 0x03,
    Crypt = 0x04,
    Ratchet = 0x05,
    Chain = 0x06,
}

/// A [`Write`] implementation which combines all written data into a single `Mix` operation and
/// passes all writes to an inner writer.
#[cfg(feature = "std")]
#[derive(Debug)]
pub struct MixWriter<W> {
    state: Sha256,
    inner: W,
    total: u64,
}

#[cfg(feature = "std")]
impl<W: Write> MixWriter<W> {
    /// Finishes the `Mix` operation and returns the inner [`Protocol`] and writer.
    #[inline]
    pub fn into_inner(self) -> (Protocol, W) {
        let mut protocol = Protocol { state: self.state };
        protocol.end_op(Operation::Mix, self.total);
        (protocol, self.inner)
    }
}

#[cfg(feature = "std")]
impl<W: Write> Write for MixWriter<W> {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.total += u64::try_from(buf.len()).expect("usize should be <= u64");
        self.state.update(buf);
        self.inner.write(buf)
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use std::io::Cursor;

    use expect_test::expect;

    use super::*;

    #[test]
    fn known_answers() {
        let mut protocol = Protocol::new("com.example.kat");
        protocol.mix(b"one");
        protocol.mix(b"two");

        expect!["3f6d24ea37711c9e"].assert_eq(&hex::encode(protocol.derive_array::<8>()));

        let mut plaintext = b"this is an example".to_vec();
        protocol.encrypt(&mut plaintext);
        expect!["368ee0e2c781264276958471a2bbf634269b"].assert_eq(&hex::encode(plaintext));

        protocol.ratchet();

        let plaintext = b"this is an example";
        let mut sealed = vec![0u8; plaintext.len() + TAG_LEN];
        sealed[..plaintext.len()].copy_from_slice(plaintext);
        protocol.seal(&mut sealed);

        expect!["c042e1f16a2ed317ad6590cbc6500247d9007d8446ea1f6cd7682c845714474f1b23"]
            .assert_eq(&hex::encode(sealed));

        expect!["2e9d721872356471"].assert_eq(&hex::encode(protocol.derive_array::<8>()));
    }

    #[test]
    fn readers() {
        let mut slices = Protocol::new("com.example.streams");
        slices.mix(b"one");
        slices.mix(b"two");

        let streams = Protocol::new("com.example.streams");
        let mut streams_write = streams.mix_writer(io::sink());
        io::copy(&mut Cursor::new(b"one"), &mut streams_write)
            .expect("cursor reads and sink writes should be infallible");
        let (streams, _) = streams_write.into_inner();

        let mut output = Vec::new();
        let mut streams_write = streams.mix_writer(&mut output);
        io::copy(&mut Cursor::new(b"two"), &mut streams_write)
            .expect("cursor reads and sink writes should be infallible");
        let (mut streams, output) = streams_write.into_inner();

        assert_eq!(slices.derive_array::<16>(), streams.derive_array::<16>());
        assert_eq!(b"two".as_slice(), output);
    }

    #[test]
    fn hedging() {
        let mut hedger = Protocol::new("com.example.hedge");
        hedger.mix(b"one");
        let tag = hedger.hedge(rand::thread_rng(), &[b"two"], |clone| {
            let tag = clone.derive_array::<16>();
            (tag[0] == 0).then_some(tag)
        });

        assert_eq!(tag[0], 0);
    }

    #[test]
    fn edge_case() {
        let mut sender = Protocol::new("");
        let mut message = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        sender.encrypt(&mut message);
        let tag_s = sender.derive_array::<TAG_LEN>();

        let mut receiver = Protocol::new("");
        receiver.decrypt(&mut message);
        let tag_r = receiver.derive_array::<TAG_LEN>();

        assert_eq!(message, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(tag_s, tag_r);
    }
}
