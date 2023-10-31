use std::io::{self, Write};

use lockstitch::Protocol;
use proptest::collection::vec;
use proptest::prelude::*;

fn writes() -> impl Strategy<Value = Vec<Vec<u8>>> {
    vec(vec(any::<u8>(), 0..200), 0..100)
}

fn mix_as_slice(writes: &[Vec<u8>]) -> [u8; 16] {
    let mut protocol = Protocol::new("com.example.test");
    let combined = writes.iter().flatten().copied().collect::<Vec<u8>>();
    protocol.mix(&combined);
    protocol.derive_array()
}

fn mix_as_writer(writes: &[Vec<u8>]) -> [u8; 16] {
    let protocol = Protocol::new("com.example.test");
    let mut writer = protocol.mix_writer(io::sink());
    for buf in writes.iter() {
        writer.write_all(buf).expect("sink writes should be infallible");
    }
    let (mut protocol, _) = writer.into_inner();
    protocol.derive_array()
}

fn encrypt_as_slice(writes: &[Vec<u8>]) -> (Vec<u8>, [u8; 16]) {
    let mut protocol = Protocol::new("com.example.test");
    let mut plaintext = writes.iter().flatten().copied().collect::<Vec<u8>>();
    protocol.encrypt(&mut plaintext);
    (plaintext, protocol.derive_array())
}

fn encrypt_as_writer(writes: &[Vec<u8>]) -> (Vec<u8>, [u8; 16]) {
    let protocol = Protocol::new("com.example.test");
    let mut ciphertext = Vec::new();
    let mut writer = protocol.encrypt_writer(&mut ciphertext);
    for buf in writes.iter() {
        writer.write_all(buf).expect("vec writes should be infallible");
    }
    let (mut protocol, _) = writer.into_inner().expect("vec writes should be infallible");
    (ciphertext, protocol.derive_array())
}

fn decrypt_as_slice(writes: &[Vec<u8>]) -> (Vec<u8>, [u8; 16]) {
    let mut protocol = Protocol::new("com.example.test");
    let mut ciphertext = writes.iter().flatten().copied().collect::<Vec<u8>>();
    protocol.decrypt(&mut ciphertext);
    (ciphertext, protocol.derive_array())
}

fn decrypt_as_writer(writes: &[Vec<u8>]) -> (Vec<u8>, [u8; 16]) {
    let protocol = Protocol::new("com.example.test");
    let mut plaintext = Vec::new();
    let mut writer = protocol.decrypt_writer(&mut plaintext);
    for buf in writes.iter() {
        writer.write_all(buf).expect("vec writes should be infallible");
    }
    let (mut protocol, _) = writer.into_inner().expect("vec writes should be infallible");
    (plaintext, protocol.derive_array())
}

proptest! {
    #![proptest_config(ProptestConfig::with_source_file("writers"))]

    #[test]
    fn mix_writer(writes in writes()) {
        let tag = mix_as_slice(&writes);
        let tag_p = mix_as_writer(&writes);

        prop_assert_eq!(tag, tag_p);
    }

    #[test]
    fn encrypt_writer(writes in writes()) {
        let (ciphertext, tag) = encrypt_as_slice(&writes);
        let (ciphertext_p, tag_p) = encrypt_as_writer(&writes);

        prop_assert_eq!(ciphertext, ciphertext_p);
        prop_assert_eq!(tag, tag_p);
    }

    #[test]
    fn decrypt_writer(writes in writes()) {
        let (plaintext, tag) = decrypt_as_slice(&writes);
        let (plaintext_p, tag_p) = decrypt_as_writer(&writes);

        prop_assert_eq!(plaintext, plaintext_p);
        prop_assert_eq!(tag, tag_p);
    }
}
