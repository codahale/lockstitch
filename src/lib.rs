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

use blake3::Hasher;
use constant_time_eq::constant_time_eq;

#[cfg(feature = "hedge")]
use rand_core::{CryptoRng, RngCore};

mod aegis128l;

/// The length of an authentication tag in bytes.
pub const TAG_LEN: usize = 16;

/// A stateful object providing fine-grained symmetric-key cryptographic services like hashing,
/// message authentication codes, pseudo-random functions, authenticated encryption, and more.
#[derive(Debug, Clone)]
pub struct Protocol {
    state: Hasher,
}

impl Protocol {
    /// Create a new protocol with the given domain.
    #[inline(always)]
    pub fn new(domain: &'static str) -> Protocol {
        // Begin with BLAKE3 in KDF mode.
        Protocol { state: Hasher::new_derive_key(domain) }
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
        let mut buf = [0u8; 64 * 1024]; // 64KiB is big enough to enable all possible SIMD optimizations
        let mut n = 0;

        loop {
            match reader.read(&mut buf) {
                Ok(0) => break, // EOF
                Ok(x) => {
                    self.state.update(&buf[..x]);
                    writer.write_all(&buf[..x])?;
                    n += u64::try_from(x).expect("unexpected overflow");
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
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
        let output_key = self.chain();

        // Fill the buffer with keystream output.
        aegis128l::prf(&output_key, &[Operation::Derive as u8; 16], out, &[]);

        // Update the BLAKE3 hasher with the output length.
        self.state.update(&(out.len() as u64).to_le_bytes());

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
        let output_key = self.chain();

        // Encrypt the plaintext.
        let tag = aegis128l::encrypt(&output_key, &[Operation::Crypt as u8; 16], in_out, &[]);

        // Update the BLAKE3 hasher with the resulting tag.
        self.state.update(&tag);

        // Update the state with the operation code and tag length.
        self.end_op(Operation::Crypt, TAG_LEN as u64);
    }

    /// Decrypt the given slice in place.
    #[inline(always)]
    pub fn decrypt(&mut self, in_out: &mut [u8]) {
        // Chain the protocol's key and generate an output key.
        let output_key = self.chain();

        // Decrypt the ciphertext.
        let tag = aegis128l::decrypt(&output_key, &[Operation::Crypt as u8; 16], in_out, &[]);

        // Update the BLAKE3 hasher with the resulting tag.
        self.state.update(&tag);

        // Update the state with the operation code and tag length.
        self.end_op(Operation::Crypt, TAG_LEN as u64);
    }

    /// Seals the given mutable slice in place.
    ///
    /// The last `TAG_LEN` bytes of the slice will be overwritten with the authentication tag.
    #[inline(always)]
    pub fn seal(&mut self, in_out: &mut [u8]) {
        // Split the buffer into plaintext and tag.
        let (in_out, tag_out) = in_out.split_at_mut(in_out.len() - TAG_LEN);

        // Chain the protocol's key and generate an output key.
        let output_key = self.chain();

        // Encrypt the plaintext.
        let tag = aegis128l::encrypt(&output_key, &[Operation::AuthCrypt as u8; 16], in_out, &[]);
        tag_out.copy_from_slice(&tag);

        // Update the BLAKE3 hasher with the resulting tag.
        self.state.update(&tag);

        // Update the state with the operation code and tag length.
        self.end_op(Operation::AuthCrypt, TAG_LEN as u64);
    }

    /// Opens the given mutable slice in place. Returns the plaintext slice of `in_out` if the input
    /// was authenticated. The last `TAG_LEN` bytes of the slice will be unmodified.
    #[inline(always)]
    #[must_use]
    pub fn open<'a>(&mut self, in_out: &'a mut [u8]) -> Option<&'a [u8]> {
        // Split the buffer into ciphertext and tag.
        let (in_out, tag) = in_out.split_at_mut(in_out.len() - TAG_LEN);

        // Chain the protocol's key and generate an output key.
        let output_key = self.chain();

        // Decrypt the ciphertext.
        let tag_p = aegis128l::decrypt(&output_key, &[Operation::AuthCrypt as u8; 16], in_out, &[]);

        // Update the BLAKE3 hasher with the resulting tag.
        self.state.update(&tag_p);

        // Update the state with the operation code and tag length.
        self.end_op(Operation::AuthCrypt, TAG_LEN as u64);

        // Check the tag.
        if constant_time_eq(tag, &tag_p) {
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
        let _ = self.chain();

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
        for _ in 0..1000 {
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

        unreachable!("unable to hedge a valid value in 1000 tries");
    }

    /// Replace the protocol's state with derived output and return an AEGIS128L output key.
    #[inline(always)]
    #[must_use]
    fn chain(&mut self) -> [u8; 16] {
        // Generate two keys' worth of XOF output from the current state.
        let mut xof_block = [0u8; blake3::KEY_LEN + 16];
        self.state.finalize_xof().fill(&mut xof_block);

        // Split the XOF output into a BLAKE3 chain key and an AEGIS128L output key.
        let (chain_key, output_key) = xof_block.split_at(blake3::KEY_LEN);

        // Use the chain key to replace the protocol's state with a new keyed hasher.
        self.state = Hasher::new_keyed(&chain_key.try_into().expect("invalid BLAKE3 key"));

        // Use the output key to create an AEGIS128L key for output.
        output_key.try_into().expect("invalid AEGIS128L key")
    }

    /// End an operation, including the number of bytes processed.
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
    Mix = 0x01,
    Derive = 0x02,
    Crypt = 0x03,
    AuthCrypt = 0x04,
    Ratchet = 0x05,
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn known_answers() {
        let mut protocol = Protocol::new("com.example.kat");
        protocol.mix(b"one");
        protocol.mix(b"two");

        assert_eq!("0914194389f16590", hex::encode(protocol.derive_array::<8>()));

        let mut plaintext = b"this is an example".to_vec();
        protocol.encrypt(&mut plaintext);
        assert_eq!("cda793cd0630a4ee770b24ba9bc66993dd21", hex::encode(plaintext));

        protocol.ratchet();

        let plaintext = b"this is an example";
        let mut sealed = vec![0u8; plaintext.len() + TAG_LEN];
        sealed[..plaintext.len()].copy_from_slice(plaintext);
        protocol.seal(&mut sealed);

        assert_eq!(
            "841cc6eb83e65fa6d6a1970f7661ed0bcb0621c51372cf51e89f026accea5bb9cc85",
            hex::encode(sealed)
        );

        assert_eq!("6f42c5270b31c5b6", hex::encode(protocol.derive_array::<8>()));
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
}
