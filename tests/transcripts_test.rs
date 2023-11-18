use std::ops::Bound;

use bolero::TypeGenerator;
use lockstitch::{Protocol, TAG_LEN};

#[derive(Clone, Debug, PartialEq)]
enum Input {
    Mix(Vec<u8>, Vec<u8>),
    Derive(Vec<u8>, usize),
    Encrypt(Vec<u8>, Vec<u8>),
    Decrypt(Vec<u8>, Vec<u8>),
    Seal(Vec<u8>, Vec<u8>),
    Open(Vec<u8>, Vec<u8>),
}

impl TypeGenerator for Input {
    fn generate<D: bolero::Driver>(driver: &mut D) -> Option<Self> {
        Some(match driver.gen_u8(Bound::Included(&0), Bound::Excluded(&5))? {
            0 => Input::Mix(driver.gen()?, driver.gen()?),
            1 => Input::Derive(
                driver.gen()?,
                driver.gen_usize(Bound::Included(&1), Bound::Included(&1024))?,
            ),
            2 => Input::Encrypt(driver.gen()?, driver.gen()?),
            3 => Input::Decrypt(driver.gen()?, driver.gen()?),
            4 => Input::Seal(driver.gen()?, driver.gen()?),
            // No way to produce valid inputs for Open operations.
            _ => unreachable!(),
        })
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

impl TypeGenerator for Transcript {
    fn generate<D: bolero::Driver>(driver: &mut D) -> Option<Self> {
        let mut t = Transcript { domain: driver.gen()?, inputs: driver.gen()? };

        // All transcripts must end with a Derive operation to capture the final protocol state.
        t.inputs.push(Input::Derive(b"final".to_vec(), 16));

        Some(t)
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
        })
        .collect();

    (Transcript { domain: t.domain.clone(), inputs }, derived)
}

/// Multiple applications of the same inputs must always produce the same outputs.
#[test]
fn determinism() {
    bolero::check!().with_type::<Transcript>().for_each(|t| {
        let a = apply_transcript(t);
        let b = apply_transcript(t);

        assert_eq!(a, b);
    });
}

/// Two different transcripts must produce different outputs.
#[test]
fn divergence() {
    bolero::check!().with_type::<(Transcript, Transcript)>().for_each(|(t0, t1)| {
        let a = apply_transcript(t0);
        let b = apply_transcript(t1);

        if t0 == t1 {
            assert_eq!(a, b);
        } else {
            assert_ne!(a, b);
        }
    });
}

/// For any transcript, invertible operations (e.g. encrypt/decrypt, seal/open) must produce
/// matching outputs to inputs.
#[test]
fn invertible() {
    bolero::check!().with_type::<Transcript>().for_each(|t| {
        let (t_inv, a_d) = invert_transcript(t);
        let (t_p, b_d) = invert_transcript(&t_inv);

        assert_eq!(t, &t_p);
        assert_eq!(a_d, b_d);
    });
}
