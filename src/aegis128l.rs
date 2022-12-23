mod ffi {
    use core::ffi::c_int;

    extern "C" {
        pub fn crypto_aead_aegis128l_encrypt_detached(
            c: *mut u8,
            mac: *mut u8,
            m: *const u8,
            mlen: usize,
            ad: *const u8,
            adlen: usize,
            npub: *const u8,
            k: *const u8,
        ) -> c_int;

        pub fn crypto_aead_aegis128l_decrypt_detached(
            m: *mut u8,
            c: *const u8,
            clen: usize,
            mac: *const u8,
            ad: *const u8,
            adlen: usize,
            npub: *const u8,
            k: *const u8,
        ) -> c_int;
    }
}

pub fn encrypt(key: &[u8; 16], nonce: &[u8; 16], ad: &[u8], mc: &mut [u8]) -> [u8; 16] {
    let mut tag = [0u8; 16];
    unsafe {
        ffi::crypto_aead_aegis128l_encrypt_detached(
            mc.as_mut_ptr(),
            tag.as_mut_ptr(),
            mc.as_ptr(),
            mc.len(),
            ad.as_ptr(),
            ad.len(),
            nonce.as_ptr(),
            key.as_ptr(),
        );
    }
    tag
}

pub fn decrypt(key: &[u8; 16], nonce: &[u8; 16], ad: &[u8], mc: &mut [u8]) -> [u8; 16] {
    let mut tag = [0u8; 16];
    unsafe {
        ffi::crypto_aead_aegis128l_decrypt_detached(
            mc.as_mut_ptr(),
            mc.as_ptr(),
            mc.len(),
            tag.as_mut_ptr(),
            ad.as_ptr(),
            ad.len(),
            nonce.as_ptr(),
            key.as_ptr(),
        )
    };
    tag
}

#[cfg(test)]
mod tests {
    use super::*;

    use aegis::aegis128l::Aegis128L;
    use proptest::array;
    use proptest::collection::vec;
    use proptest::prelude::*;

    #[test]
    fn round_trip() {
        let mut in_out = [69u8; 22];
        let tag_a = encrypt(&[12; 16], &[13; 16], &[], &mut in_out);
        let tag_b = decrypt(&[12; 16], &[13; 16], &[], &mut in_out);
        assert_eq!(in_out, [69u8; 22]);
        assert_eq!(tag_a, tag_b);
    }

    proptest! {
        #[test]
        fn decrypting_from_rust_aegis(
            k in array::uniform16(0u8..), n in array::uniform16(0u8..),
            ad in vec(any::<u8>(), 0..200), m in vec(any::<u8>(), 1..200),
        ) {
            let official = Aegis128L::new(&k, &n);
            let (c, tag_e) = official.encrypt(&m, &ad);
            let mut p = c.to_vec();
            let tag_d = decrypt(&k, &n, &ad, &mut p);

            prop_assert_eq!(m, p, "invalid decrypted plaintext");
            prop_assert_eq!(tag_e, tag_d, "invalid decrypted tag");
        }

        #[test]
        fn encrypting_to_rust_aegis(
            k in array::uniform16(0u8..), n in array::uniform16(0u8..),
            ad in vec(any::<u8>(), 0..200), m in vec(any::<u8>(), 1..200),
        ) {
            let mut c = m.clone();
            let tag = encrypt(&k, &n, &ad, &mut c);

            let official = Aegis128L::new(&k, &n);
            let p = official.decrypt(&c, &tag, &ad);

            prop_assert_eq!(Ok(m), p, "invalid decrypted plaintext");
        }
    }
}
