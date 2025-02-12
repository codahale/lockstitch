#[cfg(all(target_arch = "aarch64", feature = "asm"))]
pub use self::aarch64::*;

#[cfg(not(feature = "asm"))]
pub use self::portable::*;

#[cfg(all(any(target_arch = "x86_64", target_arch = "x86"), feature = "asm"))]
pub use self::x86_64::*;

#[cfg(all(target_arch = "aarch64", feature = "asm"))]
mod aarch64;

#[cfg(not(feature = "asm"))]
mod portable;

#[cfg(all(any(target_arch = "x86_64", target_arch = "x86"), feature = "asm"))]
mod x86_64;

/// The length of an AES block.
pub const AES_BLOCK_LEN: usize = 16;

/// Loads two AES blocks from the given slice.
#[inline]
pub fn load_2x(bytes: &[u8]) -> (AesBlock, AesBlock) {
    let (hi, lo) = bytes.split_at(AES_BLOCK_LEN);
    (load(hi), load(lo))
}

/// Stores two AES blocks in the given slice.
#[inline]
pub fn store_2x(bytes: &mut [u8], hi: AesBlock, lo: AesBlock) {
    let (b_hi, b_lo) = bytes.split_at_mut(AES_BLOCK_LEN);
    store(b_hi, hi);
    store(b_lo, lo);
}

#[cfg(test)]
mod tests {
    use expect_test::expect;
    use hex_literal::hex;

    use super::*;

    #[test]
    fn block_xor() {
        let a = load(b"ayellowsubmarine");
        let b = load(b"tuneintotheocho!");
        let c = xor(a, b);

        let mut c_bytes = [0u8; 16];
        store(&mut c_bytes, c);

        expect!["150c0b090501031c010a080e11010144"].assert_eq(&hex::encode(c_bytes));
    }

    #[test]
    fn block_xor3() {
        let a = load(b"ayellowsubmarine");
        let b = load(b"tuneintotheocho!");
        let c = load(b"mambonumbereight");
        let d = xor3(a, b, c);

        let mut d_bytes = [0u8; 16];
        store(&mut d_bytes, d);

        expect!["786d666b6a6f7671636f7a6b78666930"].assert_eq(&hex::encode(d_bytes));
    }

    #[test]
    fn block_and() {
        let a = load(b"ayellowsubmarine");
        let b = load(b"tuneintotheocho!");
        let c = and(a, b);

        let mut c_bytes = [0u8; 16];
        store(&mut c_bytes, c);

        expect!["60716464686e74637460656162686e21"].assert_eq(&hex::encode(c_bytes));
    }

    #[test]
    fn aes_round_test_vector() {
        let a = load(&hex!("000102030405060708090a0b0c0d0e0f"));
        let b = load(&hex!("101112131415161718191a1b1c1d1e1f"));
        let out = enc(a, b);
        let mut c = [0u8; 16];
        store(&mut c, out);

        expect!["7a7b4e5638782546a8c0477a3b813f43"].assert_eq(&hex::encode(c));
    }
}
