#![cfg_attr(not(feature = "std"), no_std)]
#![doc = include_str!("../README.md")]
#![warn(missing_docs)]

use crate::aegis_128l::Aegis128L;

use cmov::CmovEq;
use sha3::{
    digest::{ExtendableOutputReset, Update, XofReader},
    TurboShake128, TurboShake128Core,
};

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
    transcript: TurboShake128,
}

impl Protocol {
    /// Creates a new protocol with the given domain.
    #[inline]
    pub fn new(domain: &str) -> Protocol {
        // Initialize a protocol with an empty transcript.
        let mut protocol =
            Protocol { transcript: TurboShake128::from_core(TurboShake128Core::new(0x22)) };

        // Append the Init op header to the transcript with the domain as the label.
        //
        //   0x01 || domain || right_encode(|domain|)
        protocol.op_header(OpCode::Init, domain);

        protocol
    }

    /// Mixes the given label and slice into the protocol state.
    #[inline]
    pub fn mix(&mut self, label: &str, input: &[u8]) {
        // Append a Mix op header with the label to the transcript.
        //
        //   0x02 || label || right_encode(|label|)
        self.op_header(OpCode::Mix, label);

        // Append the input to the transcript with right-encoded length.
        //
        //   input || right_encode(|input|)
        self.transcript.update(input);
        self.transcript.update(right_encode(&mut [0u8; 9], input.len() as u64 * 8));
    }

    /// Moves the protocol into a [`std::io::Write`] implementation, mixing all written data in a
    /// single operation and passing all writes to `inner`.
    ///
    /// Use [`MixWriter::into_inner`] to finish the operation and recover the protocol and `inner`.
    #[inline]
    #[cfg(feature = "std")]
    pub fn mix_writer<W: std::io::Write>(mut self, label: &str, inner: W) -> MixWriter<W> {
        // Append a Mix op header with the label to the transcript.
        self.op_header(OpCode::Mix, label);

        // Move the protocol to a MixWriter.
        MixWriter { protocol: self, inner, len: 0 }
    }

    /// Derives output from the protocol's current state and fills the given slice with it.
    ///
    /// The output is dependent on the protocol's prior transcript, the label, and the length of
    /// `out`.
    #[inline]
    pub fn derive(&mut self, label: &str, out: &mut [u8]) {
        // Append a Derive op header with the label to the transcript.
        //
        //   0x03 || label || right_encode(|label|)
        self.op_header(OpCode::Derive, label);

        // Perform a Mix operation with the output length.
        self.mix("len", right_encode(&mut [0u8; 9], out.len() as u64 * 8));

        // Hash the transcript with TurboSHAKE128 and reset it to the empty string.
        let mut xof = self.transcript.finalize_xof_reset();

        // Generate 32+N bytes of TurboSHAKE128 output.
        let mut kdk = [0u8; 32];
        xof.read(&mut kdk);
        xof.read(out);

        // Begin the new transcript with a Mix operation using the KDK as input.
        self.mix("kdk", &kdk);
    }

    /// Derives output from the protocol's current state and returns it as an `N`-byte array.
    #[inline]
    pub fn derive_array<const N: usize>(&mut self, label: &str) -> [u8; N] {
        let mut out = [0u8; N];
        self.derive(label, &mut out);
        out
    }

    /// Encrypts the given slice in place.
    #[inline]
    pub fn encrypt(&mut self, label: &str, in_out: &mut [u8]) {
        // Append a Crypt op header with the label to the transcript.
        //
        //   0x04 || label || right_encode(|label|)
        self.op_header(OpCode::Crypt, label);

        // Perform a Mix operation with the plaintext length.
        self.mix("len", right_encode(&mut [0u8; 9], in_out.len() as u64 * 8));

        // Derive an AEGIS-128L key and nonce.
        let kn = self.derive_array::<32>("key");
        let (k, n) = kn.split_at(16);
        let mut aegis = Aegis128L::new(
            k.try_into().expect("should be 16 bytes"),
            n.try_into().expect("should be 16 bytes"),
        );

        // Encrypt the plaintext.
        aegis.encrypt(in_out);

        // Finalize the AEGIS-128L tags.
        let (_, tag256) = aegis.finalize();

        // Perform a Mix operation with the 256-bit AEGIS-128L tag.
        self.mix("tag", &tag256);
    }

    /// Decrypts the given slice in place.
    #[inline]
    pub fn decrypt(&mut self, label: &str, in_out: &mut [u8]) {
        // Append a Crypt op header with the label to the transcript.
        //
        //   0x04 || label || right_encode(|label|)
        self.op_header(OpCode::Crypt, label);

        // Perform a Mix operation with the plaintext length.
        self.mix("len", right_encode(&mut [0u8; 9], in_out.len() as u64 * 8));

        // Derive an AEGIS-128L key and nonce.
        let kn = self.derive_array::<32>("key");
        let (k, n) = kn.split_at(16);
        let mut aegis = Aegis128L::new(
            k.try_into().expect("should be 16 bytes"),
            n.try_into().expect("should be 16 bytes"),
        );

        // Decrypt the ciphertext.
        aegis.decrypt(in_out);

        // Finalize the AEGIS-128L tags.
        let (_, tag256) = aegis.finalize();

        // Perform a Mix operation with the 256-bit AEGIS-128L tag.
        self.mix("tag", &tag256);
    }

    /// Seals the given mutable slice in place.
    ///
    /// The last [`TAG_LEN`] bytes of the slice will be overwritten with the authentication tag.
    #[inline]
    pub fn seal(&mut self, label: &str, in_out: &mut [u8]) {
        // Split the buffer into plaintext and tag.
        let (in_out, tag128_out) = in_out.split_at_mut(in_out.len() - TAG_LEN);

        // Append an AuthCrypt op header with the label to the transcript.
        //
        //   0x05 || label || right_encode(|label|)
        self.op_header(OpCode::AuthCrypt, label);

        // Perform a Mix operation with the plaintext length.
        self.mix("len", right_encode(&mut [0u8; 9], in_out.len() as u64 * 8));

        // Derive an AEGIS-128L key and nonce.
        let kn = self.derive_array::<32>("key");
        let (k, n) = kn.split_at(16);
        let mut aegis = Aegis128L::new(
            k.try_into().expect("should be 16 bytes"),
            n.try_into().expect("should be 16 bytes"),
        );

        // Encrypt the plaintext.
        aegis.encrypt(in_out);

        // Finalize the AEGIS-128L tags.
        let (tag128, tag256) = aegis.finalize();

        // Append the 128-bit AEGIS-128L tag to the ciphertext.
        tag128_out.copy_from_slice(&tag128);

        // Perform a Mix operation with the 256-bit AEGIS-128L tag.
        self.mix("tag", &tag256);
    }

    /// Opens the given mutable slice in place. Returns the plaintext slice of `in_out` if the input
    /// was authenticated. The last [`TAG_LEN`] bytes of the slice will be unmodified.
    #[inline]
    #[must_use]
    pub fn open<'ct>(&mut self, label: &str, in_out: &'ct mut [u8]) -> Option<&'ct [u8]> {
        // Split the buffer into ciphertext and tag.
        let (in_out, tag128_in) = in_out.split_at_mut(in_out.len() - TAG_LEN);

        // Append an AuthCrypt op header with the label to the transcript.
        //
        //   0x05 || label || right_encode(|label|)
        self.op_header(OpCode::AuthCrypt, label);

        // Perform a Mix operation with the plaintext length.
        self.mix("len", right_encode(&mut [0u8; 9], in_out.len() as u64 * 8));

        // Derive an AEGIS-128L key and nonce.
        let kn = self.derive_array::<32>("key");
        let (k, n) = kn.split_at(16);
        let mut aegis = Aegis128L::new(
            k.try_into().expect("should be 16 bytes"),
            n.try_into().expect("should be 16 bytes"),
        );

        // Decrypt the ciphertext.
        aegis.decrypt(in_out);

        // Finalize the AEGIS-128L tags.
        let (tag128, tag256) = aegis.finalize();

        // Perform a Mix operation with the 256-bit AEGIS-128L tag.
        self.mix("tag", &tag256);

        // Check the tag against the counterfactual tag in constant time.
        if ct_eq(tag128_in, &tag128) {
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

    /// Appends an operation header with an optional label to the protocol transcript.
    #[inline]
    fn op_header(&mut self, op_code: OpCode, label: &str) {
        // Append the operation code and label to the transcript:
        //
        //   op_code || label || right_encode(|label|)
        self.transcript.update(&[op_code as u8]);
        self.transcript.update(label.as_bytes());
        self.transcript.update(right_encode(&mut [0u8; 9], label.len() as u64 * 8));
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
        self.protocol.transcript.update(right_encode(&mut [0u8; 9], self.len * 8));
        (self.protocol, self.inner)
    }
}

#[cfg(feature = "std")]
impl<W: std::io::Write> std::io::Write for MixWriter<W> {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // Track the written length.
        self.len += buf.len() as u64;
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

/// Compares two slices for equality in constant time.
#[inline]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    let mut res = 1;
    a.cmovne(b, 0, &mut res);
    res != 0
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
    fn known_answers() {
        let mut protocol = Protocol::new("com.example.kat");
        protocol.mix("first", b"one");
        protocol.mix("second", b"two");

        expect!["9d741fc2d9c5cba0"].assert_eq(&hex::encode(protocol.derive_array::<8>("third")));

        let mut plaintext = b"this is an example".to_vec();
        protocol.encrypt("fourth", &mut plaintext);
        expect!["ec324ce127e09da0b60bf87199acd016969a"].assert_eq(&hex::encode(plaintext));

        let plaintext = b"this is an example";
        let mut sealed = vec![0u8; plaintext.len() + TAG_LEN];
        sealed[..plaintext.len()].copy_from_slice(plaintext);
        protocol.seal("fifth", &mut sealed);

        expect!["9aec57dd29ad1dfd45ca56098e26bdbb928d39e23c9bf64a712a9d04adfab8803707"]
            .assert_eq(&hex::encode(sealed));

        expect!["21d58fc6560a5c49"].assert_eq(&hex::encode(protocol.derive_array::<8>("sixth")));
    }

    #[test]
    fn readers() {
        let mut slices = Protocol::new("com.example.streams");
        slices.mix("first", b"one");
        slices.mix("second", b"two");

        let streams = Protocol::new("com.example.streams");
        let mut streams_write = streams.mix_writer("first", io::sink());
        io::copy(&mut Cursor::new(b"one"), &mut streams_write)
            .expect("cursor reads and sink writes should be infallible");
        let (streams, _) = streams_write.into_inner();

        let mut output = Vec::new();
        let mut streams_write = streams.mix_writer("second", &mut output);
        io::copy(&mut Cursor::new(b"two"), &mut streams_write)
            .expect("cursor reads and sink writes should be infallible");
        let (mut streams, output) = streams_write.into_inner();

        assert_eq!(slices.derive_array::<16>("third"), streams.derive_array::<16>("third"));
        assert_eq!(b"two".as_slice(), output);
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
