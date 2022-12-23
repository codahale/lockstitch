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

    #[test]
    fn round_trip() {
        let mut in_out = [69u8; 22];
        let tag_a = encrypt(&[12; 16], &[13; 16], &[], &mut in_out);
        let tag_b = decrypt(&[12; 16], &[13; 16], &[], &mut in_out);
        assert_eq!(in_out, [69u8; 22]);
        assert_eq!(tag_a, tag_b);
    }

    #[test]
    fn test_aegis_in_place() {
        let m = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let ad = b"Comment numero un";
        let key = b"YELLOW SUBMARINE";
        let nonce = [0u8; 16];

        let mut mc = m.to_vec();
        let tag_e = encrypt(key, &nonce, ad, &mut mc);
        let expected_mc = [
            137, 147, 98, 134, 30, 108, 100, 90, 185, 139, 110, 255, 169, 201, 98, 232, 138, 159,
            166, 71, 169, 80, 96, 205, 2, 109, 22, 101, 71, 138, 231, 79, 130, 148, 159, 175, 131,
            148, 166, 200, 180, 159, 139, 138, 80, 104, 188, 50, 89, 53, 204, 111, 12, 212, 196,
            143, 98, 25, 129, 118, 132, 115, 95, 13, 232, 167, 13, 59, 19, 143, 58, 59, 42, 206,
            238, 139, 2, 251, 194, 222, 185, 59, 143, 116, 231, 175, 233, 67, 229, 11, 219, 127,
            160, 215, 89, 217, 109, 89, 76, 225, 102, 118, 69, 94, 252, 2, 69, 205, 251, 65, 159,
            177, 3, 101,
        ];
        let expected_tag = [16, 244, 133, 167, 76, 40, 56, 136, 6, 235, 61, 139, 252, 7, 57, 150];
        assert_eq!(mc, expected_mc);
        assert_eq!(tag_e, expected_tag);

        let tag_d = decrypt(key, &nonce, ad, &mut mc);
        assert_eq!(mc, m);
        assert_eq!(tag_d, expected_tag);
    }
}
