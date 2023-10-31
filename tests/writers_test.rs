use std::io::{self, Write};

use lockstitch::Protocol;
use proptest::collection::vec;
use proptest::prelude::*;

fn writes() -> impl Strategy<Value = Vec<Vec<u8>>> {
    vec(vec(any::<u8>(), 0..200), 0..100)
}

proptest! {
    #![proptest_config(ProptestConfig::with_source_file("writers"))]

    #[test]
    fn mix_writer(writes in writes()) {
        let mut slices = Protocol::new("com.example.test");
        let combined = writes.iter().flatten().copied().collect::<Vec<u8>>();
        slices.mix(&combined);

        let writer = Protocol::new("com.example.test");
        let mut writer = writer.mix_writer(io::sink());
        for buf in writes {
            writer.write_all(&buf).expect("sink writes should be infallible");
        }
        let (mut writer, _) = writer.into_inner();

        prop_assert_eq!(slices.derive_array::<16>(), writer.derive_array::<16>(),
            "two mixes of the same writes produced different outputs");
    }

    #[test]
    fn encrypt_writer(writes in writes()) {
        let mut slices = Protocol::new("com.example.test");
        let mut ciphertext = writes.iter().flatten().copied().collect::<Vec<u8>>();
        slices.encrypt(&mut ciphertext);

        let writer = Protocol::new("com.example.test");
        let mut ciphertext_p = Vec::new();
        let mut writer = writer.encrypt_writer(&mut ciphertext_p);
        for buf in writes.iter() {
            writer.write_all(buf).expect("sink writes should be infallible");
        }
        let (mut writer, _) = writer.into_inner().expect("");

        prop_assert_eq!(ciphertext, ciphertext_p);
        prop_assert_eq!(slices.derive_array::<16>(), writer.derive_array::<16>(),
            "two encrypts of the same writes produced different outputs");
    }

    #[test]
    fn decrypt_writer(writes in writes()) {
        let mut slices = Protocol::new("com.example.test");
        let mut plaintext = writes.iter().flatten().copied().collect::<Vec<u8>>();
        slices.decrypt(&mut plaintext);

        let writer = Protocol::new("com.example.test");
        let mut plaintext_p = Vec::new();
        let mut writer = writer.decrypt_writer(&mut plaintext_p);
        for buf in writes.iter() {
            writer.write_all(buf).expect("sink writes should be infallible");
        }
        let (mut writer, _) = writer.into_inner().expect("");

        prop_assert_eq!(plaintext, plaintext_p);
        prop_assert_eq!(slices.derive_array::<16>(), writer.derive_array::<16>(),
            "two decrypts of the same writes produced different outputs");
    }
}
