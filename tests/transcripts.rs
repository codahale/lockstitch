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
    Tagged([u8; TAG_LEN]),
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
            Input::Tag => Some(Output::Tagged(protocol.tag_array())),
            Input::Ratchet => {
                protocol.ratchet();
                None
            }
        })
        .collect()
}

fn invert_transcript(t: &Transcript) -> (Transcript, Vec<Vec<u8>>, Vec<[u8; 16]>) {
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
                tagged.push(protocol.tag_array());
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
        Just(Input::Ratchet),
        Just(Input::Tag),
        (1usize..256).prop_map(Input::Derive),
        data().prop_map(Input::Mix),
        data().prop_map(Input::Encrypt),
        data().prop_map(Input::Decrypt),
    ]
}

prop_compose! {
    /// A transcript of 0..62 arbitrary operations terminated with a `Tag` operation to capture
    /// the duplex's final state.
    fn transcript()(
        domain: String,
        mut inputs in vec(input(), 0..62),
    ) -> Transcript{
        inputs.push(Input::Tag);
        Transcript{domain, inputs}
    }
}

proptest! {
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

    /// For any transcript, reversible outputs (e.g. encrypt/decrypt) must be symmetric.
    #[test]
    fn symmetry(t in transcript()) {
        let (t_inv, a_d, a_t) = invert_transcript(&t);
        let (t_p, b_d, b_t) = invert_transcript(&t_inv);

        prop_assert_eq!(t, t_p, "unable to invert a transcript: {:?}", t_inv);
        prop_assert_eq!(a_d, b_d, "divergent derived outputs");
        prop_assert_eq!(a_t, b_t, "divergent tagged outputs");
    }
}
