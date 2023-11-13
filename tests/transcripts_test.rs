use std::num::NonZeroUsize;

use lockstitch::{Protocol, TAG_LEN};
use quickcheck::Arbitrary;
use quickcheck_macros::quickcheck;

#[derive(Clone, Debug, PartialEq)]
enum Input {
    Mix(Vec<u8>, Vec<u8>),
    Derive(Vec<u8>, usize),
    Encrypt(Vec<u8>, Vec<u8>),
    Decrypt(Vec<u8>, Vec<u8>),
    Seal(Vec<u8>, Vec<u8>),
    Open(Vec<u8>, Vec<u8>),
    Ratchet,
}

impl Arbitrary for Input {
    fn arbitrary(g: &mut quickcheck::Gen) -> Self {
        match g.choose(&[0, 1, 2, 3, 4, 5]).expect("should choose a variant") {
            0 => Input::Mix(Vec::<u8>::arbitrary(g), Vec::<u8>::arbitrary(g)),
            1 => {
                Input::Derive(Vec::<u8>::arbitrary(g), NonZeroUsize::arbitrary(g).get() % (1 << 12))
            }
            2 => Input::Encrypt(Vec::<u8>::arbitrary(g), Vec::<u8>::arbitrary(g)),
            3 => Input::Decrypt(Vec::<u8>::arbitrary(g), Vec::<u8>::arbitrary(g)),
            4 => Input::Seal(Vec::<u8>::arbitrary(g), Vec::<u8>::arbitrary(g)),
            5 => Input::Ratchet,
            // No way to produce valid inputs for Open operations.
            _ => unreachable!(),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
enum Output {
    Derived(Vec<u8>),
    Encrypted(Vec<u8>),
    Decrypted(Vec<u8>),
    Sealed(Vec<u8>),
    Opened(Vec<u8>),
}

#[derive(Clone, Debug, PartialEq)]
struct Transcript {
    domain: String,
    inputs: Vec<Input>,
}

impl Arbitrary for Transcript {
    fn arbitrary(g: &mut quickcheck::Gen) -> Self {
        let mut inputs = Vec::<Input>::arbitrary(g);

        // All transcripts must end with a Derive operation to capture the final protocol state.
        inputs.push(Input::Derive(b"final".to_vec(), 16));

        Self { domain: String::arbitrary(g), inputs }
    }
}

fn apply_transcript(t: &Transcript) -> Vec<Output> {
    let mut protocol = Protocol::new(&t.domain);
    t.inputs
        .iter()
        .cloned()
        .flat_map(|op| match op {
            Input::Mix(ref label, ref data) => {
                protocol.mix(label, data);
                None
            }
            Input::Derive(ref label, n) => {
                let mut out = vec![0u8; n];
                protocol.derive(label, &mut out);
                Some(Output::Derived(out))
            }
            Input::Encrypt(ref label, mut plaintext) => {
                protocol.encrypt(label, &mut plaintext);
                Some(Output::Encrypted(plaintext))
            }
            Input::Decrypt(ref label, mut ciphertext) => {
                protocol.decrypt(label, &mut ciphertext);
                Some(Output::Decrypted(ciphertext))
            }
            Input::Seal(ref label, ref plaintext) => {
                let mut ciphertext = vec![0u8; plaintext.len() + TAG_LEN];
                ciphertext[..plaintext.len()].copy_from_slice(plaintext);

                protocol.seal(label, &mut ciphertext);
                Some(Output::Sealed(ciphertext))
            }
            Input::Open(ref label, mut ciphertext) => {
                protocol.open(label, &mut ciphertext).map(|p| Output::Opened(p.to_vec()))
            }
            Input::Ratchet => {
                protocol.ratchet();
                None
            }
        })
        .collect()
}

fn invert_transcript(t: &Transcript) -> (Transcript, Vec<Vec<u8>>) {
    let mut protocol = Protocol::new(&t.domain);
    let mut derived = Vec::new();
    let inputs = t
        .inputs
        .iter()
        .cloned()
        .map(|op| match op {
            Input::Mix(label, data) => {
                protocol.mix(&label, &data);
                Input::Mix(label, data)
            }
            Input::Derive(label, n) => {
                let mut out = vec![0u8; n];
                protocol.derive(&label, &mut out);
                derived.push(out);
                Input::Derive(label, n)
            }
            Input::Encrypt(label, mut plaintext) => {
                protocol.encrypt(&label, &mut plaintext);
                Input::Decrypt(label, plaintext)
            }
            Input::Decrypt(label, mut ciphertext) => {
                protocol.decrypt(&label, &mut ciphertext);
                Input::Encrypt(label, ciphertext)
            }
            Input::Seal(label, plaintext) => {
                let mut ciphertext = vec![0u8; plaintext.len() + TAG_LEN];
                ciphertext[..plaintext.len()].copy_from_slice(&plaintext);

                protocol.seal(&label, &mut ciphertext);
                Input::Open(label, ciphertext)
            }
            Input::Open(label, mut ciphertext) => {
                let plaintext =
                    protocol.open(&label, &mut ciphertext).map(|p| p.to_vec()).unwrap_or_default();
                Input::Seal(label, plaintext)
            }
            Input::Ratchet => {
                protocol.ratchet();
                Input::Ratchet
            }
        })
        .collect();

    (Transcript { domain: t.domain.clone(), inputs }, derived)
}

/// Multiple applications of the same inputs must always produce the same outputs.
#[quickcheck]
fn qc_determinism(t: Transcript) -> bool {
    let a = apply_transcript(&t);
    let b = apply_transcript(&t);

    a == b
}

/// Two different transcripts must produce different outputs.
#[quickcheck]
fn qc_divergence(t0: Transcript, t1: Transcript) -> bool {
    let a = apply_transcript(&t0);
    let b = apply_transcript(&t1);

    t0 == t1 || a != b
}

/// For any transcript, invertible operations (e.g. encrypt/decrypt, seal/open) must produce
/// matching outputs to inputs.
#[quickcheck]
fn qc_invertible(t: Transcript) -> bool {
    let (t_inv, a_d) = invert_transcript(&t);
    let (t_p, b_d) = invert_transcript(&t_inv);

    t == t_p && a_d == b_d
}
