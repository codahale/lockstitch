use lockstitch::{Protocol, TAG_LEN};
use proptest::collection::vec;
use proptest::prelude::*;

#[derive(Clone, Debug, PartialEq)]
enum Input {
    Mix(Vec<u8>),
    Derive(usize),
    Encrypt(Vec<u8>),
    Decrypt(Vec<u8>),
    Tag,
    Ratchet,
}

#[derive(Clone, Debug, PartialEq)]
enum Output {
    Derived(Vec<u8>),
    Encrypted(Vec<u8>),
    Decrypted(Vec<u8>),
    Tagged(Vec<u8>),
}

#[derive(Clone, Debug, PartialEq)]
struct Transcript {
    domain: String,
    inputs: Vec<Input>,
}

fn apply_transcript(t: &Transcript) -> Vec<Output> {
    // Leak the domain so we can pretend we've statically allocated it in this test.
    let domain: &'static str = Box::leak(Box::new(t.domain.clone()).into_boxed_str());
    let mut protocol = Protocol::new(domain);
    t.inputs
        .iter()
        .cloned()
        .flat_map(|op| match op {
            Input::Mix(data) => {
                protocol.mix(&data);
                None
            }
            Input::Derive(n) => {
                let mut out = vec![0u8; n];
                protocol.derive(&mut out);
                Some(Output::Derived(out))
            }
            Input::Encrypt(mut plaintext) => {
                protocol.encrypt(&mut plaintext);
                Some(Output::Encrypted(plaintext))
            }
            Input::Decrypt(mut ciphertext) => {
                protocol.decrypt(&mut ciphertext);
                Some(Output::Decrypted(ciphertext))
            }
            Input::Tag => {
                let mut tag = vec![0u8; TAG_LEN];
                protocol.tag(&mut tag);
                Some(Output::Tagged(tag))
            }
            Input::Ratchet => {
                protocol.ratchet();
                None
            }
        })
        .collect()
}

fn invert_transcript(t: &Transcript) -> (Transcript, Vec<Vec<u8>>, Vec<Vec<u8>>) {
    // Leak the domain so we can pretend we've statically allocated it in this test.
    let domain: &'static str = Box::leak(Box::new(t.domain.clone()).into_boxed_str());
    let mut protocol = Protocol::new(domain);
    let mut derived = Vec::new();
    let mut tagged = Vec::new();
    let inputs = t
        .inputs
        .iter()
        .cloned()
        .map(|op| match op {
            Input::Mix(data) => {
                protocol.mix(&data);
                Input::Mix(data.to_vec())
            }
            Input::Derive(n) => {
                let mut out = vec![0u8; n];
                protocol.derive(&mut out);
                derived.push(out);
                Input::Derive(n)
            }
            Input::Encrypt(mut plaintext) => {
                protocol.encrypt(&mut plaintext);
                Input::Decrypt(plaintext)
            }
            Input::Decrypt(mut ciphertext) => {
                protocol.decrypt(&mut ciphertext);
                Input::Encrypt(ciphertext)
            }
            Input::Tag => {
                let mut tag = vec![0u8; TAG_LEN];
                protocol.tag(&mut tag);
                tagged.push(tag);
                Input::Tag
            }
            Input::Ratchet => {
                protocol.ratchet();
                Input::Ratchet
            }
        })
        .collect();

    (Transcript { domain: t.domain.clone(), inputs }, derived, tagged)
}

fn data() -> impl Strategy<Value = Vec<u8>> {
    vec(any::<u8>(), 0..200)
}

fn input() -> impl Strategy<Value = Input> {
    prop_oneof![
        Just(Input::Tag),
        Just(Input::Ratchet),
        (1usize..256).prop_map(Input::Derive),
        data().prop_map(Input::Mix),
        data().prop_map(Input::Encrypt),
        data().prop_map(Input::Decrypt),
    ]
}

prop_compose! {
    /// A transcript of 0..62 arbitrary operations terminated with a `Tag` operation to capture the
    /// duplex's final state.
    fn transcript()(
        domain: String,
        mut inputs in vec(input(), 0..62),
    ) -> Transcript{
        inputs.push(Input::Tag);
        Transcript{domain, inputs}
    }
}

proptest! {
    /// Any two equal transcripts must produce equal outputs. Any two different transcripts must
    /// produce different outputs.
    #[test]
    fn transcript_consistency(t0 in transcript(), t1 in transcript()) {
        let out0 = apply_transcript(&t0);
        let out1 = apply_transcript(&t1);

        if t0 == t1 {
            prop_assert_eq!(out0, out1, "equal transcripts produced different outputs");
        } else  {
            prop_assert_ne!(out0, out1, "different transcripts produced equal outputs");
        }
    }

    /// For any transcript, reversible outputs (e.g. encrypt/decrypt) must be symmetric.
    #[test]
    fn transcript_symmetry(t in transcript()) {
        let (t_inv, a_d, a_t) = invert_transcript(&t);
        let (t_p, b_d, b_t) = invert_transcript(&t_inv);

        prop_assert_eq!(t, t_p, "non-commutative transcript inversion");
        prop_assert_eq!(a_d, b_d, "divergent derived outputs");
        prop_assert_eq!(a_t, b_t, "divergent tag outputs");
    }
}
