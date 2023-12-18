#![cfg_attr(not(feature = "std"), no_std)]
#![doc = include_str!("../README.md")]
#![warn(missing_docs)]

use core::{fmt::Debug, mem};

use crate::aegis_128l::Aegis128L;

use aegis_256::Aegis256;
use hkdf::{Hkdf, HkdfExtract};
use sha2::{Sha256, Sha512};
pub use subtle;
use subtle::ConstantTimeEq;

mod aegis_128l;
mod aegis_256;
mod intrinsics;

#[cfg(feature = "docs")]
#[doc = include_str!("../design.md")]
pub mod design {}

#[cfg(feature = "docs")]
#[doc = include_str!("../perf.md")]
pub mod perf {}

/// The length of an authentication tag in bytes.
pub const TAG_LEN: usize = 16;

mod private {
    /// A trait whose implementations are limited to this crate.
    pub trait Sealed {}
}

/// A wrapper trait for the AEGIS-128L and AEGIS-256 implementations.
pub trait Aegis {
    /// Encrypts the given slice in place.
    fn encrypt(&mut self, in_out: &mut [u8]);

    /// Decrypts the given slice in place.
    fn decrypt(&mut self, in_out: &mut [u8]);

    /// Finalizes the cipher state into a pair of 128-bit and 256-bit authentication tags.
    fn finalize(self) -> ([u8; 16], [u8; 32]);
}

/// A typeclass trait for the two different security levels provided. The two available
/// implementations are [`B128`], which combines HKDF-SHA-256 and AEGIS-128L to offer 128-bit
/// security, and [`B256`], which combines HKDF-SHA-512 and AEGIS-256 to offer 256-bit security.
pub trait SecurityLevel: private::Sealed + Clone + Copy {
    /// The type of the transcript used.
    type Transcript: Debug + Clone;

    /// The type of the pseudo-random key extracted from the transcript.
    type Prk;

    /// The type of AEGIS cipher used.
    type Cipher: Aegis;

    /// Creates a new, empty transcript.
    fn new_transcript() -> Self::Transcript;

    /// Appends the data to the transcript.
    fn append(t: &mut Self::Transcript, data: &[u8]);

    /// Extracts a PRK from the transcript.
    fn extract_prk(t: Self::Transcript) -> Self::Prk;

    /// Derives a value from the PRK given an info string.
    fn derive(prk: &Self::Prk, info: &[u8], out: &mut [u8]);

    /// Initializes a new cipher using the given key generation callback.
    fn new_cipher(key_gen: impl FnOnce(&mut [u8])) -> Self::Cipher;
}

/// The 128-bit security level, combining HKDF-SHA-256 and AEGIS-128L for very high performance.
#[derive(Debug, Clone, Copy)]
pub struct B128;

impl private::Sealed for B128 {}

impl SecurityLevel for B128 {
    type Transcript = HkdfExtract<Sha256>;

    type Prk = Hkdf<Sha256>;

    type Cipher = Aegis128L;

    #[inline]
    fn new_transcript() -> Self::Transcript {
        HkdfExtract::new(None)
    }

    #[inline]
    fn append(t: &mut Self::Transcript, data: &[u8]) {
        t.input_ikm(data);
    }

    #[inline]
    fn extract_prk(t: Self::Transcript) -> Self::Prk {
        let (_, prk) = t.finalize();
        prk
    }

    #[inline]
    fn new_cipher(key_gen: impl FnOnce(&mut [u8])) -> Self::Cipher {
        let mut kn = [0u8; 32];
        key_gen(&mut kn);
        Aegis128L::new(
            kn[..16].try_into().expect("should be 16 bytes"),
            kn[16..].try_into().expect("should be 16 bytes"),
        )
    }

    #[inline]
    fn derive(prk: &Self::Prk, info: &[u8], out: &mut [u8]) {
        prk.expand(info, out).expect("should derive output");
    }
}

/// The 256-bit security level, combining HKDF-SHA-512 and AEGIS-256 for high performance.
#[derive(Debug, Clone, Copy)]
pub struct B256;

impl private::Sealed for B256 {}

impl SecurityLevel for B256 {
    type Transcript = HkdfExtract<Sha512>;

    type Prk = Hkdf<Sha512>;

    type Cipher = Aegis256;

    #[inline]
    fn new_transcript() -> Self::Transcript {
        HkdfExtract::new(None)
    }

    #[inline]
    fn append(t: &mut Self::Transcript, data: &[u8]) {
        t.input_ikm(data);
    }

    #[inline]
    fn extract_prk(t: Self::Transcript) -> Self::Prk {
        let (_, prk) = t.finalize();
        prk
    }

    #[inline]
    fn new_cipher(key_gen: impl FnOnce(&mut [u8])) -> Self::Cipher {
        let mut kn = [0u8; 64];
        key_gen(&mut kn);
        Aegis256::new(
            kn[..32].try_into().expect("should be 32 bytes"),
            kn[32..].try_into().expect("should be 32 bytes"),
        )
    }

    #[inline]
    fn derive(prk: &Self::Prk, info: &[u8], out: &mut [u8]) {
        prk.expand(info, out).expect("should derive output");
    }
}

/// A stateful object providing fine-grained symmetric-key cryptographic services like hashing,
/// message authentication codes, pseudo-random functions, authenticated encryption, and more.
#[derive(Debug, Clone)]
pub struct Protocol<S: SecurityLevel> {
    transcript: S::Transcript,
}

impl<S> Protocol<S>
where
    S: SecurityLevel,
{
    /// Creates a new protocol with the given domain.
    #[inline]
    pub fn new(domain: &str) -> Protocol<S> {
        // Initialize a protocol with an empty transcript.
        let mut protocol = Protocol { transcript: S::new_transcript() };

        // Append the Init op header to the transcript with the domain as the label.
        //
        //   0x01 || domain || right_encode(|domain|)
        protocol.op_header(OpCode::Init, domain.as_bytes());

        protocol
    }

    /// Mixes the given label and slice into the protocol state.
    #[inline]
    pub fn mix(&mut self, label: &[u8], input: &[u8]) {
        // Append a Mix op header with the label to the transcript.
        //
        //   0x02 || label || right_encode(|label|)
        self.op_header(OpCode::Mix, label);

        // Append the input to the transcript with right-encoded length.
        //
        //   input || right_encode(|input|)
        S::append(&mut self.transcript, input);
        S::append(&mut self.transcript, right_encode(&mut [0u8; 9], input.len() as u64 * 8));
    }

    /// Moves the protocol into a [`Write`] implementation, mixing all written data in a single
    /// operation and passing all writes to `inner`.
    ///
    /// Use [`MixWriter::into_inner`] to finish the operation and recover the protocol and `inner`.
    #[inline]
    #[cfg(feature = "std")]
    pub fn mix_writer<W: std::io::Write>(mut self, label: &[u8], inner: W) -> MixWriter<S, W> {
        // Append a Mix op header with the label to the transcript.
        self.op_header(OpCode::Mix, label);

        // Move the protocol to a MixWriter.
        MixWriter { protocol: self, inner, len: 0 }
    }

    /// Derives output from the protocol's current state and fills the given slice with it.
    #[inline]
    pub fn derive(&mut self, label: &[u8], out: &mut [u8]) {
        // Append a Derive op header with the label to the transcript.
        //
        //   0x03 || label || right_encode(|label|)
        self.op_header(OpCode::Derive, label);

        // Calculate HKDF-Extract("", transcript) and clear the transcript.
        let transcript = mem::replace(&mut self.transcript, S::new_transcript());
        let prk = S::extract_prk(transcript);

        // Use HKDF-Expand to derive a new KDF key and the requested output.
        let mut kdf_key = [0u8; 32];
        S::derive(&prk, b"kdf-key", &mut kdf_key);
        S::derive(&prk, b"output", out);

        // Perform a Mix operation with the KDF key.
        self.mix(b"kdf-key", &kdf_key);

        // Perform a Mix operation with the output length.
        self.mix(b"len", right_encode(&mut [0u8; 9], out.len() as u64 * 8));
    }

    /// Derives output from the protocol's current state and returns it as an `N`-byte array.
    #[inline]
    pub fn derive_array<const N: usize>(&mut self, label: &[u8]) -> [u8; N] {
        let mut out = [0u8; N];
        self.derive(label, &mut out);
        out
    }

    /// Encrypts the given slice in place.
    #[inline]
    pub fn encrypt(&mut self, label: &[u8], in_out: &mut [u8]) {
        // Append a Crypt op header with the label to the transcript.
        //
        //   0x04 || label || right_encode(|label|)
        self.op_header(OpCode::Crypt, label);

        // Derive an AEGIS-128L key and nonce.
        let mut aegis = S::new_cipher(|kn| self.derive(b"key", kn));

        // Encrypt the plaintext.
        aegis.encrypt(in_out);

        // Finalize the AEGIS-128L tags.
        let (_, tag256) = aegis.finalize();

        // Perform a Mix operation with the 256-bit AEGIS-128L tag.
        self.mix(b"tag", &tag256);
    }

    /// Decrypts the given slice in place.
    #[inline]
    pub fn decrypt(&mut self, label: &[u8], in_out: &mut [u8]) {
        // Append a Crypt op header with the label to the transcript.
        //
        //   0x04 || label || right_encode(|label|)
        self.op_header(OpCode::Crypt, label);

        // Derive an AEGIS-128L key and nonce.
        let mut aegis = S::new_cipher(|kn| self.derive(b"key", kn));

        // Decrypt the ciphertext.
        aegis.decrypt(in_out);

        // Finalize the AEGIS-128L tags.
        let (_, tag256) = aegis.finalize();

        // Perform a Mix operation with the 256-bit AEGIS-128L tag.
        self.mix(b"tag", &tag256);
    }

    /// Seals the given mutable slice in place.
    ///
    /// The last [`TAG_LEN`] bytes of the slice will be overwritten with the authentication tag.
    #[inline]
    pub fn seal(&mut self, label: &[u8], in_out: &mut [u8]) {
        // Split the buffer into plaintext and tag.
        let (in_out, tag128_out) = in_out.split_at_mut(in_out.len() - TAG_LEN);

        // Append an AuthCrypt op header with the label to the transcript.
        //
        //   0x05 || label || right_encode(|label|)
        self.op_header(OpCode::AuthCrypt, label);

        // Derive an AEGIS-128L key and nonce.
        let mut aegis = S::new_cipher(|kn| self.derive(b"key", kn));

        // Encrypt the plaintext.
        aegis.encrypt(in_out);

        // Finalize the AEGIS-128L tags.
        let (tag128, tag256) = aegis.finalize();

        // Append the 128-bit AEGIS-128L tag to the ciphertext.
        tag128_out.copy_from_slice(&tag128);

        // Perform a Mix operation with the 256-bit AEGIS-128L tag.
        self.mix(b"tag", &tag256);
    }

    /// Opens the given mutable slice in place. Returns the plaintext slice of `in_out` if the input
    /// was authenticated. The last [`TAG_LEN`] bytes of the slice will be unmodified.
    #[inline]
    #[must_use]
    pub fn open<'ct>(&mut self, label: &[u8], in_out: &'ct mut [u8]) -> Option<&'ct [u8]> {
        // Split the buffer into ciphertext and tag.
        let (in_out, tag128_in) = in_out.split_at_mut(in_out.len() - TAG_LEN);

        // Append an AuthCrypt op header with the label to the transcript.
        //
        //   0x05 || label || right_encode(|label|)
        self.op_header(OpCode::AuthCrypt, label);

        // Derive an AEGIS-128L key and nonce.
        let mut aegis = S::new_cipher(|kn| self.derive(b"key", kn));

        // Decrypt the ciphertext.
        aegis.decrypt(in_out);

        // Finalize the AEGIS-128L tags.
        let (tag128, tag256) = aegis.finalize();

        // Perform a Mix operation with the 256-bit AEGIS-128L tag.
        self.mix(b"tag", &tag256);

        // Check the tag against the counterfactual tag in constant time.
        if tag128_in.ct_eq(&tag128).into() {
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
        mut rng: impl rand_core::CryptoRngCore,
        secrets: &[impl AsRef<[u8]>],
        max_tries: usize,
        f: impl Fn(&mut Self) -> Option<R>,
    ) -> R {
        for _ in 0..max_tries {
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

        unreachable!("unable to hedge a valid value in {} tries", max_tries);
    }

    /// Appends an operation header with an optional label to the protocol transcript.
    #[inline]
    fn op_header(&mut self, op_code: OpCode, label: &[u8]) {
        // Append the operation code and label to the transcript:
        //
        //   op_code || label || right_encode(|label|)
        S::append(&mut self.transcript, &[op_code as u8]);
        S::append(&mut self.transcript, label);
        S::append(&mut self.transcript, right_encode(&mut [0u8; 9], label.len() as u64 * 8));
    }
}

/// All Lockstitch operation types.
#[derive(Debug, Clone, Copy)]
enum OpCode {
    /// Initialize a protocol with a domain separation string.
    Init = 0x01,
    /// Mix a labeled input into the protocol transcript.
    Mix = 0x02,
    /// Derive a labeled output from the protocol transcript.
    Derive = 0x03,
    /// Encrypt or decrypt a labeled input using the protocol transcript as a key.
    Crypt = 0x04,
    /// Seal or open a labeled input using the protocol transcript as a key.
    AuthCrypt = 0x05,
}

/// A [`std::io::Write`] implementation which combines all written data into a single `Mix`
/// operation and passes all writes to an inner writer.
#[cfg(feature = "std")]
#[derive(Debug)]
pub struct MixWriter<S: SecurityLevel, W> {
    protocol: Protocol<S>,
    inner: W,
    len: u64,
}

#[cfg(feature = "std")]
impl<S: SecurityLevel, W: std::io::Write> MixWriter<S, W> {
    /// Finishes the `Mix` operation and returns the inner [`Protocol`] and writer.
    #[inline]
    pub fn into_inner(mut self) -> (Protocol<S>, W) {
        // Append the right-encoded length to the transcript.
        S::append(&mut self.protocol.transcript, right_encode(&mut [0u8; 9], self.len * 8));
        (self.protocol, self.inner)
    }
}

#[cfg(feature = "std")]
impl<S: SecurityLevel, W: std::io::Write> std::io::Write for MixWriter<S, W> {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // Track the written length.
        self.len += buf.len() as u64;
        // Append the written slice to the protocol transcript.
        S::append(&mut self.protocol.transcript, buf);
        // Pass the slice to the inner writer and return the result.
        self.inner.write(buf)
    }

    #[inline]
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Encodes a value using [NIST SP 800-185][]'s `right_encode`.
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
    fn known_answers_128() {
        let mut protocol = Protocol::<B128>::new("com.example.kat");
        protocol.mix(b"first", b"one");
        protocol.mix(b"second", b"two");

        expect!["4d8a58dbd43b1870"].assert_eq(&hex::encode(protocol.derive_array::<8>(b"third")));

        let mut plaintext = b"this is an example".to_vec();
        protocol.encrypt(b"fourth", &mut plaintext);
        expect!["3d382e329a9c99992d7be4092b4ec1624bd1"].assert_eq(&hex::encode(plaintext));

        let plaintext = b"this is an example";
        let mut sealed = vec![0u8; plaintext.len() + TAG_LEN];
        sealed[..plaintext.len()].copy_from_slice(plaintext);
        protocol.seal(b"fifth", &mut sealed);

        expect!["f200ec2bc1189c94f41235b5d86d58c83250670bc7a1ef052fca9ca3662a7ba735b7"]
            .assert_eq(&hex::encode(sealed));

        expect!["57b0bf5b2934356d"].assert_eq(&hex::encode(protocol.derive_array::<8>(b"sixth")));
    }

    #[test]
    fn known_answers_256() {
        let mut protocol = Protocol::<B256>::new("com.example.kat");
        protocol.mix(b"first", b"one");
        protocol.mix(b"second", b"two");

        expect!["3815c12afa86b3f0"].assert_eq(&hex::encode(protocol.derive_array::<8>(b"third")));

        let mut plaintext = b"this is an example".to_vec();
        protocol.encrypt(b"fourth", &mut plaintext);
        expect!["61c4565f968f0b1e94a040bb1f6abc81607a"].assert_eq(&hex::encode(plaintext));

        let plaintext = b"this is an example";
        let mut sealed = vec![0u8; plaintext.len() + TAG_LEN];
        sealed[..plaintext.len()].copy_from_slice(plaintext);
        protocol.seal(b"fifth", &mut sealed);

        expect!["6f3ca466b1326974f6b36891b48e09cf08cbacccd12fe959a71e9e41772fbe301608"]
            .assert_eq(&hex::encode(sealed));

        expect!["71b771900301a2e8"].assert_eq(&hex::encode(protocol.derive_array::<8>(b"sixth")));
    }

    #[test]
    fn readers() {
        let mut slices = Protocol::<B128>::new("com.example.streams");
        slices.mix(b"first", b"one");
        slices.mix(b"second", b"two");

        let streams = Protocol::<B128>::new("com.example.streams");
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
        let mut hedger = Protocol::<B128>::new("com.example.hedge");
        hedger.mix(b"first", b"one");
        let tag = hedger.hedge(rand::thread_rng(), &[b"two"], 10_000, |clone| {
            let tag = clone.derive_array::<16>(b"tag");
            (tag[0] == 0).then_some(tag)
        });

        assert_eq!(tag[0], 0);
    }

    #[test]
    fn edge_case() {
        let mut sender = Protocol::<B128>::new("");
        let mut message = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        sender.encrypt(b"message", &mut message);
        let tag_s = sender.derive_array::<TAG_LEN>(b"tag");

        let mut receiver = Protocol::<B128>::new("");
        receiver.decrypt(b"message", &mut message);
        let tag_r = receiver.derive_array::<TAG_LEN>(b"tag");

        assert_eq!(message, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(tag_s, tag_r);
    }

    #[test]
    fn right_encode_injective() {
        bolero::check!().with_type::<(u64, u64)>().cloned().for_each(|(a, b)| {
            let mut buf_a = [0u8; 9];
            let mut buf_b = [0u8; 9];

            let a_e = right_encode(&mut buf_a, a);
            let b_e = right_encode(&mut buf_b, b);

            if a == b {
                assert_eq!(a_e, b_e);
            } else {
                assert_ne!(a_e, b_e);
            }
        });
    }

    #[test]
    fn encoded_label_injective() {
        bolero::check!().with_type::<(Vec<u8>, Vec<u8>)>().cloned().for_each(|(a, b)| {
            let mut a_e = a.clone();
            a_e.extend_from_slice(right_encode(&mut [0u8; 9], a.len() as u64 * 8));

            let mut b_e = b.clone();
            b_e.extend_from_slice(right_encode(&mut [0u8; 9], b.len() as u64 * 8));

            if a == b {
                assert_eq!(a_e, b_e, "equal labels must have equal encoded forms");
            } else {
                assert_ne!(a_e, b_e, "non-equal labels must have non-equal encoded forms");
            }
        });
    }

    #[test]
    fn right_encode_test_vectors() {
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
