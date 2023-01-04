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

#[cfg(feature = "std")]
use std::io::{self, Read, Write};

use constant_time_eq::constant_time_eq;
#[cfg(feature = "hedge")]
use rand_core::{CryptoRng, RngCore};
use rocca_s::RoccaS;
use sha2::digest::FixedOutputReset;
use sha2::{Digest, Sha256};

#[doc = include_str!("../design.md")]
pub mod design {}

#[doc = include_str!("../perf.md")]
pub mod perf {}

mod rocca_s;

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
    #[inline(always)]
    pub fn new(domain: &'static str) -> Protocol {
        // Create a protocol with a fresh SHA-256 instance.
        let mut protocol = Protocol { state: Sha256::new() };

        // Update the state with the domain string.
        protocol.state.update(domain.as_bytes());

        // End the INIT operation with the domain string length in bytes.
        protocol.end_op(Operation::Init, domain.len() as u64);

        protocol
    }

    /// Mixes the given slice into the protocol state.
    #[inline(always)]
    pub fn mix(&mut self, data: &[u8]) {
        // Update the state with the given slice.
        self.state.update(data);

        // Update the state with the operation code and byte count.
        self.end_op(Operation::Mix, data.len() as u64);
    }

    /// Mixes the contents of the reader into the protocol state.
    ///
    /// # Errors
    ///
    /// Returns any errors returned by the reader or writer.
    #[cfg(feature = "std")]
    pub fn mix_stream(&mut self, reader: impl Read) -> io::Result<u64> {
        self.copy_stream(reader, io::sink())
    }

    /// Mixes the contents of the reader into the protocol state while copying them to the writer.
    ///
    /// # Errors
    ///
    /// Returns any errors returned by the reader or writer.
    #[cfg(feature = "std")]
    pub fn copy_stream(
        &mut self,
        mut reader: impl Read,
        mut writer: impl Write,
    ) -> io::Result<u64> {
        let mut buf = [0u8; 64 * 1024];
        let mut n = 0;

        loop {
            match reader.read(&mut buf) {
                Ok(0) => break, // EOF
                Ok(x) => {
                    self.state.update(&buf[..x]);
                    writer.write_all(&buf[..x])?;
                    n += u64::try_from(x).expect("unexpected overflow");
                }
                Err(e) => return Err(e),
            }
        }

        // Update the state with the operation code and byte count.
        self.end_op(Operation::Mix, n);

        Ok(n)
    }

    /// Derive output from the protocol's current state and fill the given slice with it.
    #[inline(always)]
    pub fn derive(&mut self, out: &mut [u8]) {
        // Chain the protocol's key and generate an output key.
        let mut output = self.chain(Operation::Derive);

        // Fill the buffer with PRF output.
        output.prf(out);

        // Update the state with the output length.
        self.state.update((out.len() as u64).to_le_bytes());

        // Update the state with the operation code and integer length.
        self.end_op(Operation::Derive, 8);
    }

    /// Derive output from the protocol's current state and return it as an array.
    #[inline(always)]
    pub fn derive_array<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        self.derive(&mut out);
        out
    }

    /// Encrypt the given slice in place.
    #[inline(always)]
    pub fn encrypt(&mut self, in_out: &mut [u8]) {
        // Chain the protocol's key and generate an output key.
        let mut output = self.chain(Operation::Crypt);

        // Encrypt the plaintext.
        output.encrypt(in_out);

        // Calculate the tag.
        let tag = output.tag();

        // Update the state with the resulting tag.
        self.state.update(tag);

        // Update the state with the operation code and tag length.
        self.end_op(Operation::Crypt, tag.len() as u64);
    }

    /// Decrypt the given slice in place.
    #[inline(always)]
    pub fn decrypt(&mut self, in_out: &mut [u8]) {
        // Chain the protocol's key and generate an output key.
        let mut output = self.chain(Operation::Crypt);

        // Decrypt the plaintext.
        output.decrypt(in_out);

        // Calculate the tag.
        let tag = output.tag();

        // Update the state with the resulting tag.
        self.state.update(tag);

        // Update the state with the operation code and tag length.
        self.end_op(Operation::Crypt, tag.len() as u64);
    }

    /// Seals the given mutable slice in place.
    ///
    /// The last `TAG_LEN` bytes of the slice will be overwritten with the authentication tag.
    #[inline(always)]
    pub fn seal(&mut self, in_out: &mut [u8]) {
        // Split the buffer into plaintext and tag.
        let (in_out, tag_out) = in_out.split_at_mut(in_out.len() - TAG_LEN);

        // Chain the protocol's key and generate an output key.
        let mut output = self.chain(Operation::AuthCrypt);

        // Encrypt the plaintext.
        output.encrypt(in_out);

        // Calculate the tag.
        let tag = output.tag();

        // Append the first half of the tag to the ciphertext.
        tag_out.copy_from_slice(&tag[..TAG_LEN]);

        // Update the state with the resulting tag.
        self.state.update(tag);

        // Update the state with the operation code and tag length.
        self.end_op(Operation::AuthCrypt, tag.len() as u64);
    }

    /// Opens the given mutable slice in place. Returns the plaintext slice of `in_out` if the input
    /// was authenticated. The last `TAG_LEN` bytes of the slice will be unmodified.
    #[inline(always)]
    #[must_use]
    pub fn open<'a>(&mut self, in_out: &'a mut [u8]) -> Option<&'a [u8]> {
        // Split the buffer into ciphertext and tag.
        let (in_out, tag) = in_out.split_at_mut(in_out.len() - TAG_LEN);

        // Chain the protocol's key and generate an output key.
        let mut output = self.chain(Operation::AuthCrypt);

        // Decrypt the plaintext.
        output.decrypt(in_out);

        // Calculate the counterfactual tag.
        let tag_p = output.tag();

        // Update the state with the resulting tag.
        self.state.update(tag_p);

        // Update the state with the operation code and tag length.
        self.end_op(Operation::AuthCrypt, tag_p.len() as u64);

        // Check the tag against the first half of the counterfactual tah.
        if constant_time_eq(tag, &tag_p[..TAG_LEN]) {
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

    /// Replace the protocol's state with derived output and return an operation-specific Rocca-S
    /// instance.
    #[inline(always)]
    #[must_use]
    fn chain(&mut self, operation: Operation) -> RoccaS {
        // Finalize the current state and reset it to an uninitialized state.
        let hash = self.state.finalize_fixed_reset();

        // Use the hash of the current state as a key for a chain Rocca-S instance.
        let mut chain = RoccaS::new(&hash.into(), &[Operation::Chain as u8; 16]);

        // Generate 64 bytes of PRF output.
        let mut prf = [0u8; 64];
        chain.prf(&mut prf);

        // Use the first 32 bytes as a chain key; use the second as an output key.
        let (chain_key, output_key) = prf.split_at(32);

        // Initialize the current state with the chain key.
        self.state.update(chain_key);
        self.end_op(Operation::Init, 32);

        // Return a Rocca-S instance keyed with the output key and using the operation code as a
        // nonce.
        RoccaS::new(&output_key.try_into().expect("invalid key len"), &[operation as u8; 16])
    }

    /// End an operation, including the number of bytes processed.
    #[inline(always)]
    fn end_op(&mut self, operation: Operation, n: u64) {
        // Allocate a buffer for output.
        let mut buffer = [0u8; 10];

        // Encode the number of bytes processed using NIST SP-800-185's right_encode.
        buffer[..8].copy_from_slice(&n.to_be_bytes());
        let offset = buffer.iter().position(|i| *i != 0).unwrap_or(7);
        buffer[8] = 8 - offset as u8;

        // Set the last byte to the operation code.
        buffer[9] = operation as u8;

        // Update the state with the length and operation code.
        self.state.update(&buffer[offset..]);
    }
}

/// A primitive operation in a protocol with a unique 1-byte code.
#[derive(Debug, Clone, Copy)]
enum Operation {
    Init = 0x01,
    Mix = 0x02,
    Derive = 0x03,
    Crypt = 0x04,
    AuthCrypt = 0x05,
    Ratchet = 0x06,
    Chain = 0x07,
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn known_answers() {
        let mut protocol = Protocol::new("com.example.kat");
        protocol.mix(b"one");
        protocol.mix(b"two");

        assert_eq!("33c45a7463fe3e49", hex::encode(protocol.derive_array::<8>()));

        let mut plaintext = b"this is an example".to_vec();
        protocol.encrypt(&mut plaintext);
        assert_eq!("71b6a741da79ee5ffe77dc33182f3774bf38", hex::encode(plaintext));

        protocol.ratchet();

        let plaintext = b"this is an example";
        let mut sealed = vec![0u8; plaintext.len() + TAG_LEN];
        sealed[..plaintext.len()].copy_from_slice(plaintext);
        protocol.seal(&mut sealed);

        assert_eq!(
            "f018bba0ecea4e7369f796a330f27e940fb4382bc3aec0ac4ee19d14c64160c7f419",
            hex::encode(sealed)
        );

        assert_eq!("4518bd12f63f9577", hex::encode(protocol.derive_array::<8>()));
    }

    #[test]
    fn streams() {
        let mut slices = Protocol::new("com.example.streams");
        slices.mix(b"one");
        slices.mix(b"two");

        let mut streams = Protocol::new("com.example.streams");
        streams.mix_stream(Cursor::new(b"one")).expect("error mixing stream");

        let mut output = Vec::new();
        streams.copy_stream(Cursor::new(b"two"), &mut output).expect("error copying stream");

        assert_eq!(slices.derive_array::<16>(), streams.derive_array::<16>());
        assert_eq!(b"two".as_slice(), &output);
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
