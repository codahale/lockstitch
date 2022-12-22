mod ffi {
    use core::ffi::c_int;

    extern "C" {
        pub fn crypto_aead_aegis128l_encrypt(
            c: *mut u8,
            mac: *mut u8,
            m: *const u8,
            mlen: usize,
            npub: *const u8,
            k: *const u8,
        ) -> c_int;

        pub fn crypto_aead_aegis128l_decrypt(
            m: *mut u8,
            c: *const u8,
            clen: usize,
            mac: *const u8,
            npub: *const u8,
            k: *const u8,
        ) -> c_int;
    }
}

pub fn encrypt(key: &[u8; 16], nonce: &[u8; 16], mc: &mut [u8]) -> [u8; 16] {
    let mut tag = [0u8; 16];
    unsafe {
        ffi::crypto_aead_aegis128l_encrypt(
            mc.as_mut_ptr(),
            tag.as_mut_ptr(),
            mc.as_ptr(),
            mc.len(),
            nonce.as_ptr(),
            key.as_ptr(),
        );
    }
    tag
}

pub fn decrypt(key: &[u8; 16], nonce: &[u8; 16], mc: &mut [u8]) -> [u8; 16] {
    let mut tag = [0u8; 16];
    unsafe {
        ffi::crypto_aead_aegis128l_decrypt(
            mc.as_mut_ptr(),
            mc.as_ptr(),
            mc.len(),
            tag.as_mut_ptr(),
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
        let tag_a = encrypt(&[12; 16], &[13; 16], &mut in_out);
        let tag_b = decrypt(&[12; 16], &[13; 16], &mut in_out);
        assert_eq!(in_out, [69u8; 22]);
        assert_eq!(tag_a, tag_b);
    }
}
