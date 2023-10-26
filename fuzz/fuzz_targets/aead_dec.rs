#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use lockstitch::{Protocol, TAG_LEN};

#[derive(Debug, Arbitrary)]
struct Input {
    key: Vec<u8>,
    nonce: Vec<u8>,
    ad: Vec<u8>,
    ciphertext: Vec<u8>,
}

fuzz_target!(|input: Input| {
    if input.ciphertext.len() < TAG_LEN {
        return;
    }

    let mut aead = Protocol::new("lockstitch.fuzz.aead");
    aead.mix(&input.key);
    aead.mix(&input.nonce);
    aead.mix(&input.ad);

    let mut ciphertext = input.ciphertext.clone();
    let _ = aead.open(&mut ciphertext);
});
