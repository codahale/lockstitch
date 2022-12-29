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
    state: RoccaS,
}

impl Protocol {
    /// Create a new protocol with the given domain.
    #[inline(always)]
    pub fn new(domain: &'static str) -> Protocol {
        // Create a protocol with a Rocca-S state using a fixed key and nonce.
        let mut protocol = Protocol { state: RoccaS::new(&[0u8; 32], &[0u8; 16]) };

        // Include the domain as authenticated data.
        protocol.state.authenticated_data(domain.as_bytes());

        // End the INIT operation with the domain string length in bytes.
        protocol.end_op(Operation::Init, domain.len() as u64);

        protocol
    }

    /// Mixes the given slice into the protocol state.
    #[inline(always)]
    pub fn mix(&mut self, data: &[u8]) {
        // Update the state with the given slice.
        self.state.authenticated_data(data);

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
        // Ensure we're always reading a full block unless we're at the end of the stream. Reading
        // partial blocks in the middle of a stream due to short reads will corrupt the protocol's
        // state via accidental padding.
        fn read_block(mut reader: impl Read, mut buf: &mut [u8]) -> io::Result<usize> {
            let max = buf.len();
            while !buf.is_empty() {
                match reader.read(buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        let tmp = buf;
                        buf = &mut tmp[n..];
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(e),
                }
            }
            Ok(max - buf.len())
        }

        let mut buf = [0u8; 64 * 1024];
        let mut n = 0;

        loop {
            match read_block(&mut reader, &mut buf) {
                Ok(0) => break, // EOF
                Ok(x) => {
                    self.state.authenticated_data(&buf[..x]);
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
        self.state.authenticated_data(&(out.len() as u64).to_le_bytes());

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
        self.state.authenticated_data(&tag);

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
        self.state.authenticated_data(&tag);

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
        self.state.authenticated_data(&tag);

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
        self.state.authenticated_data(&tag_p);

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
        // Use the tag of the current state as a key for a chain Rocca-S instance.
        let mut chain = RoccaS::new(&self.state.tag(), &[Operation::Chain as u8; 16]);

        // Generate 32 bytes of PRF output for use as a chain key.
        let mut chain_key = [0u8; 32];
        chain.prf(&mut chain_key);

        // Generate 32 bytes of PRF output for use as an output key.
        let mut output_key = [0u8; 32];
        chain.prf(&mut output_key);

        // Replace the protocol's state with a new state keyed with the chain key.
        self.state = RoccaS::new(&chain_key, &[0u8; 16]);

        // Return a Rocca-S instance keyed with the output key and using the operation code as a
        // nonce.
        RoccaS::new(&output_key, &[operation as u8; 16])
    }

    /// End an operation, including the number of bytes processed.
    fn end_op(&mut self, operation: Operation, n: u64) {
        // Allocate a message block sized buffer for output.
        let mut buffer = [0u8; 32];

        // Encode the operation length in bits as a little endian 128-bit integer.
        buffer[..16].copy_from_slice(&(n as u128 * 8).to_le_bytes());

        // Set the last byte to the operation code.
        buffer[31] = operation as u8;

        // Update the state with the length and operation code.
        self.state.authenticated_data(&buffer);
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

        assert_eq!("a745643085ee5427", hex::encode(protocol.derive_array::<8>()));

        let mut plaintext = b"this is an example".to_vec();
        protocol.encrypt(&mut plaintext);
        assert_eq!("74ebbe99151d63d59ab38ce426c3bd536bd4", hex::encode(plaintext));

        protocol.ratchet();

        let plaintext = b"this is an example";
        let mut sealed = vec![0u8; plaintext.len() + TAG_LEN];
        sealed[..plaintext.len()].copy_from_slice(plaintext);
        protocol.seal(&mut sealed);

        assert_eq!(
            "eb83519f7d103100e04dc96aecc599dc886e454f3f6c7c66061b46a6c5a4a85389d1",
            hex::encode(sealed)
        );

        assert_eq!("ee80700f4b62da0f", hex::encode(protocol.derive_array::<8>()));
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
