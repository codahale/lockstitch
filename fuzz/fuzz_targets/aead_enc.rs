#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use lockstitch::{Protocol, TAG_LEN};

#[derive(Debug, Arbitrary)]
struct Input {
    key: Vec<u8>,
    nonce: Vec<u8>,
    ad: Vec<u8>,
    plaintext: Vec<u8>,
}

fuzz_target!(|input: Input| {
    let mut aead = Protocol::new("lockstitch.fuzz.aead");
    aead.mix(b"key", &input.key);
    aead.mix(b"nonce", &input.nonce);
    aead.mix(b"ad", &input.ad);

    let mut ciphertext = input.plaintext.clone();
    ciphertext.extend_from_slice(&[0u8; TAG_LEN]);
    aead.seal(b"message", &mut ciphertext);
});
