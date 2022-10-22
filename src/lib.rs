#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
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

use std::io::{self, Read, Write};

use blake3::Hasher;
use c2_chacha::guts::ChaCha;
use constant_time_eq::constant_time_eq;

#[cfg(feature = "hedge")]
use rand_core::{CryptoRng, RngCore};

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
    pub fn new(domain: &str) -> Protocol {
        // Begin with BLAKE3 in KDF mode.
        Protocol { state: Hasher::new_derive_key(domain) }
    }

    /// Mixes the given slice into the protocol state.
    #[inline(always)]
    pub fn mix(&mut self, data: &[u8]) {
        // Update the state with the operation code.
        self.state.update(&Operation::Mix.begin());

        // Update the state with the given slice.
        self.state.update(data);

        // Update the state with the operation code and byte count.
        self.state.update(&Operation::Mix.end(data.len() as u64));
    }

    /// Mixes the contents of the reader into the protocol state.
    ///
    /// # Errors
    ///
    /// Returns any errors returned by the reader or writer.
    pub fn mix_stream(&mut self, reader: impl Read) -> io::Result<u64> {
        self.copy_stream(reader, io::sink())
    }

    /// Mixes the contents of the reader into the protocol state while copying them to the writer.
    ///
    /// # Errors
    ///
    /// Returns any errors returned by the reader or writer.
    pub fn copy_stream(
        &mut self,
        mut reader: impl Read,
        mut writer: impl Write,
    ) -> io::Result<u64> {
        // Update the state with the operation code.
        self.state.update(&Operation::Mix.begin());

        // 64KiB is a large enough buffer to enable all possible optimizations.
        let mut buf = [0u8; 1024 * 64];
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
        self.state.update(&Operation::Mix.end(n));

        Ok(n)
    }

    /// Derive output from the protocol's current state and fill the given slice with it.
    #[inline(always)]
    pub fn derive(&mut self, out: &mut [u8]) {
        // Update the state with the operation code.
        self.state.update(&Operation::Derive.begin());

        // Chain the protocol's key and key a ChaCha8 instance.
        let mut chacha = self.chain();

        // Fill the output buffer with ChaCha8 output.
        if out.len() <= 64 {
            // If the output is less than a single block (e.g. a key or scalar), favor latency over
            // throughput.
            let mut tmp = [0u8; 64];
            chacha.fill_narrow(&mut tmp);
            out.copy_from_slice(&tmp[..out.len()]);
        } else {
            // If the output is greater than a single block, favor throughput over latency.
            let mut tmp = [0u8; 64 * 4];
            for chunk in out.chunks_mut(tmp.len()) {
                chacha.fill_wide(&mut tmp);
                chunk.copy_from_slice(&tmp[..chunk.len()]);
            }
        }

        // Update the state with the operation code and derived byte count.
        self.state.update(&Operation::Derive.end(out.len() as u64));
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
        // Update the state with the operation code.
        self.state.update(&Operation::Crypt.begin());

        // Chain the protocol's key and key a ChaCha8 instance.
        let mut chacha = self.chain();

        // Here we use the wide (4x) buffer size to enable throughput optimizations.
        let mut tmp = [0u8; 64 * 4];

        // Break the input into 64KiB chunks to enable SIMD optimizations on input.
        for chunk in in_out.chunks_mut(64 * 1024) {
            // Update the state with the plaintext.
            self.state.update(chunk);

            for plaintext in chunk.chunks_mut(tmp.len()) {
                // XOR the plaintext with ChaCha8 output to produce ciphertext.
                chacha.fill_wide(&mut tmp);
                for (p, k) in plaintext.iter_mut().zip(tmp.iter()) {
                    *p ^= *k;
                }
            }
        }

        // Update the state with the operation code and encrypted byte count.
        self.state.update(&Operation::Crypt.end(in_out.len() as u64));
    }

    /// Decrypt the given slice in place.
    #[inline(always)]
    pub fn decrypt(&mut self, in_out: &mut [u8]) {
        // Update the state with the operation code.
        self.state.update(&Operation::Crypt.begin());

        // Chain the protocol's key and key a ChaCha8 instance.
        let mut chacha = self.chain();

        // Here we use the wide (4x) buffer size to enable throughput optimizations.
        let mut tmp = [0u8; 64 * 4];

        // Break the input into 64KiB chunks to enable SIMD optimizations on input.
        for chunk in in_out.chunks_mut(64 * 1024) {
            for ciphertext in chunk.chunks_mut(tmp.len()) {
                // XOR the ciphertext with ChaCha8 output to produce plaintext.
                chacha.fill_wide(&mut tmp);
                for (c, k) in ciphertext.iter_mut().zip(tmp.iter()) {
                    *c ^= *k;
                }
            }

            // Update the state with the plaintext.
            self.state.update(chunk);
        }

        // Update the state with the operation code and decrypted byte count.
        self.state.update(&Operation::Crypt.end(in_out.len() as u64));
    }

    /// Extract output from the protocol's current state and fill the given slice with it.
    #[inline(always)]
    pub fn tag(&mut self, out: &mut [u8]) {
        // Update the state with the operation code.
        self.state.update(&Operation::Tag.begin());

        // Chain the protocol's key and key a ChaCha8 instance.
        let mut chacha = self.chain();

        // Truncate the first block of ChaCha8 output and use it as the tag.
        let mut tmp = [0u8; 64];
        chacha.fill_narrow(&mut tmp);
        out.copy_from_slice(&tmp[..TAG_LEN]);

        // Update the state with the operation code and tag length.
        self.state.update(&Operation::Tag.end(TAG_LEN as u64));
    }

    /// Check whether or not the output of [`Protocol::tag`] matches the provided tag. Returns `true` if they
    /// match; `false` otherwise.
    #[inline(always)]
    #[must_use]
    pub fn check_tag(&mut self, tag: &[u8]) -> bool {
        if tag.len() != TAG_LEN {
            return false;
        }

        let mut tag_p = [0u8; TAG_LEN];
        self.tag(&mut tag_p);
        constant_time_eq(tag, &tag_p)
    }

    /// Seals the given mutable slice in place.
    ///
    /// The last `TAG_LEN` bytes of the slice will be overwritten with the authentication tag.
    #[inline(always)]
    pub fn seal(&mut self, in_out: &mut [u8]) {
        // Split the buffer into plaintext and tag.
        let (plaintext, tag) = in_out.split_at_mut(in_out.len() - TAG_LEN);

        // Encrypt the plaintext.
        self.encrypt(plaintext);

        // Extract a tag.
        self.tag(tag);
    }

    /// Opens the given mutable slice in place. Returns the plaintext slice of `in_out` if the input
    /// was authenticated. The last `TAG_LEN` bytes of the slice will be unmodified.
    #[inline(always)]
    #[must_use]
    pub fn open<'a>(&mut self, in_out: &'a mut [u8]) -> Option<&'a [u8]> {
        // Split the buffer into ciphertext and tag.
        let (ciphertext, tag) = in_out.split_at_mut(in_out.len() - TAG_LEN);

        // Decrypt the ciphertext.
        self.decrypt(ciphertext);

        // Check the tag.
        if self.check_tag(tag) {
            Some(ciphertext)
        } else {
            // Otherwise, the ciphertext is inauthentic and we zero out the inauthentic plaintext to
            // avoid bugs where the caller forgets to check the return value of this function and
            // discloses inauthentic plaintext.
            ciphertext.fill(0);
            None
        }
    }

    /// Clone the protocol and update it with the given secrets and 64 random bytes. Pass the clone
    /// to the given function and return the result of that function.
    #[cfg(feature = "hedge")]
    #[must_use]
    pub fn hedge<R>(
        &self,
        mut rng: impl RngCore + CryptoRng,
        secrets: &[impl AsRef<[u8]>],
        f: impl Fn(&mut Self) -> Option<R>,
    ) -> R {
        loop {
            // Clone the protocol's state.
            let mut clone = self.clone();

            // Update the clone with the secrets.
            for s in secrets {
                clone.mix(s.as_ref());
            }

            // Update the clone with a random value.
            let mut r = [0u8; 64];
            rng.fill_bytes(&mut r);
            clone.mix(&r);

            // Call the given function with the clone and return if the function was successful.
            if let Some(r) = f(&mut clone) {
                return r;
            }
        }
    }

    /// Replace the protocol's state with derived output and return a `ChaCha8` instance.
    #[inline(always)]
    fn chain(&mut self) -> Output {
        // Generate 64 bytes of XOF output from the current state.
        let mut tmp = [0u8; 64];
        self.state.finalize_xof().fill(&mut tmp);

        // Split the XOF output into two parts.
        let (a, b) = tmp.split_at(32);

        // Use the first 32 bytes as the key for a new keyed BLAKE3 hasher.
        self.state = Hasher::new_keyed(&a.try_into().expect("invalid key"));

        // Use the second 32 bytes as the key for ChaCha output using an all-zero nonce.
        Output { chacha: ChaCha::new(b.try_into().expect("invalid key"), &[0u8; 8]) }
    }
}

#[derive(Debug, Clone, Copy)]
enum Operation {
    Mix = 0x01,
    Derive = 0x02,
    Crypt = 0x03,
    Tag = 0x04,
}

impl Operation {
    const fn begin(self) -> [u8; 1] {
        [self as u8]
    }

    #[inline(always)]
    fn end(self, n: u64) -> [u8; 9] {
        let mut out = [0u8; 9];
        let (code, len) = out.split_at_mut(1);
        code[0] = (self as u8) | 0b1000_0000;
        len.copy_from_slice(&n.to_le_bytes());
        out
    }
}

struct Output {
    chacha: ChaCha,
}

impl Output {
    const DROUNDS: u32 = 4; // aka ChaCha8

    #[inline(always)]
    fn fill_narrow(&mut self, out: &mut [u8; 64]) {
        self.chacha.refill(Self::DROUNDS, out);
    }

    #[inline(always)]
    fn fill_wide(&mut self, out: &mut [u8; 64 * 4]) {
        self.chacha.refill4(Self::DROUNDS, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_ops() {
        let mut sho = Protocol::new("this is a test");
        sho.mix(b"one");
        sho.mix(b"two");

        let mut one = [0u8; 10];
        sho.derive(&mut one);

        sho.mix(b"three");

        let mut two = [0u8; 10];
        sho.derive(&mut two);

        dbg!(one, two);
    }

    #[test]
    fn encrypt_decrypt() {
        let mut message = b"this is a message".to_vec();

        {
            let mut a = Protocol::new("this is a test");
            a.mix(b"this is a key");
            a.encrypt(&mut message);
        }
        {
            let mut a = Protocol::new("this is a test");
            a.mix(b"this is a key");
            a.decrypt(&mut message);
        }

        assert_eq!(b"this is a message", message.as_slice());
    }

    #[test]
    fn seal_open() {
        let mut message = b"this is a message".to_vec();
        message.extend_from_slice(&[0u8; TAG_LEN]);

        {
            let mut a = Protocol::new("this is a test");
            a.mix(b"this is a key");
            a.seal(&mut message);
        }
        {
            let mut a = Protocol::new("this is a test");
            a.mix(b"this is a key");
            assert_eq!(a.open(&mut message), Some(b"this is a message".as_slice()));
        }
    }
}
