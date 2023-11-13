use lockstitch::{Protocol, TAG_LEN};
use proptest::collection::vec;
use proptest::prelude::*;

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

fn label() -> impl Strategy<Value = Vec<u8>> {
    vec(any::<u8>(), 0..200)
}

fn data() -> impl Strategy<Value = Vec<u8>> {
    vec(any::<u8>(), 0..200)
}

fn input() -> impl Strategy<Value = Input> {
    prop_oneof![
        Just(Input::Ratchet),
        (label(), (1usize..256)).prop_map(|(l, n)| Input::Derive(l, n)),
        (label(), data()).prop_map(|(l, d)| Input::Mix(l, d)),
        (label(), data()).prop_map(|(l, d)| Input::Encrypt(l, d)),
        (label(), data()).prop_map(|(l, d)| Input::Decrypt(l, d)),
        (label(), data()).prop_map(|(l, d)| Input::Seal(l, d)),
        (label(), vec(any::<u8>(), TAG_LEN..200)).prop_map(|(l, d)| Input::Open(l, d))
    ]
}

fn invertible_input() -> impl Strategy<Value = Input> {
    prop_oneof![
        Just(Input::Ratchet),
        (label(), (1usize..256)).prop_map(|(l, n)| Input::Derive(l, n)),
        (label(), data()).prop_map(|(l, d)| Input::Mix(l, d)),
        (label(), data()).prop_map(|(l, d)| Input::Encrypt(l, d)),
        (label(), data()).prop_map(|(l, d)| Input::Decrypt(l, d)),
        (label(), data()).prop_map(|(l, d)| Input::Seal(l, d)),
        // we can't generate inputs for Open that are valid
    ]
}

prop_compose! {
    /// A transcript of 0..62 arbitrary operations terminated with a `Derive` operation to capture
    /// the duplex's final state.
    fn transcript()(
        domain: String,
        mut inputs in vec(input(), 0..62),
    ) -> Transcript{
        inputs.push(Input::Derive(b"final".to_vec(), 16));
        Transcript{domain, inputs}
    }
}

prop_compose! {
    /// A transcript of 0..62 invertible operations terminated with a `Derive` operation to capture
    /// the duplex's final state.
    fn invertible_transcript()(
        domain: String,
        mut inputs in vec(invertible_input(), 0..62),
    ) -> Transcript{
        inputs.push(Input::Derive(b"final".to_vec(), 16));
        Transcript{domain, inputs}
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_source_file("transcripts"))]

    /// Multiple applications of the same inputs must always produce the same outputs.
    #[test]
    fn determinism(t in transcript()) {
        let a = apply_transcript(&t);
        let b = apply_transcript(&t);

        prop_assert_eq!(a, b, "two runs of the same transcript produced different outputs");
    }

    /// Two different transcripts must produce different outputs.
    #[test]
    fn divergence(t0 in transcript(), t1 in transcript()) {
        prop_assume!(t0 != t1, "transcripts must be different");

        let a = apply_transcript(&t0);
        let b = apply_transcript(&t1);

        prop_assert_ne!(a, b, "different transcripts produced equal outputs");
    }

    /// For any transcript, invertible operations (e.g. encrypt/decrypt, seal/open) must produce
    /// matching outputs to inputs.
    #[test]
    fn invertible(t in invertible_transcript()) {
        let (t_inv, a_d) = invert_transcript(&t);
        let (t_p, b_d) = invert_transcript(&t_inv);

        prop_assert_eq!(t, t_p, "unable to invert a transcript");
        prop_assert_eq!(a_d, b_d, "divergent derived outputs");
    }
}
