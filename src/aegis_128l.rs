#[cfg(all(target_arch = "aarch64", not(feature = "portable")))]
use self::aarch64::*;

#[cfg(feature = "portable")]
use self::portable::*;

#[cfg(all(any(target_arch = "x86_64", target_arch = "x86"), not(feature = "portable")))]
use self::x86_64::*;

#[cfg(all(target_arch = "aarch64", not(feature = "portable")))]
mod aarch64;

#[cfg(feature = "portable")]
mod portable;

#[cfg(all(any(target_arch = "x86_64", target_arch = "x86"), not(feature = "portable")))]
mod x86_64;

/// The length of an AEGIS-128L block.
pub const BLOCK_LEN: usize = 32;

/// The length of an AES block.
pub const AES_BLOCK_LEN: usize = 16;

#[derive(Debug, Clone)]
pub struct Aegis128L {
    blocks: [AesBlock; 8],
    ad_len: u64,
    mc_len: u64,
}

impl Aegis128L {
    pub fn new(key: &[u8; AES_BLOCK_LEN], nonce: &[u8; AES_BLOCK_LEN]) -> Self {
        // Initialize constants.
        let c0 = load(&[
            0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9,
            0x79, 0x62,
        ]);
        let c1 = load(&[
            0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5,
            0x28, 0xdd,
        ]);

        // Initialize key and nonce blocks.
        let key = load(key);
        let nonce = load(nonce);

        // Initialize cipher state.
        let mut state = Aegis128L {
            blocks: [
                xor(key, nonce),
                c1,
                c0,
                c1,
                xor(key, nonce),
                xor(key, c0),
                xor(key, c1),
                xor(key, c0),
            ],
            ad_len: 0,
            mc_len: 0,
        };

        // Update the state with the nonce and key 10 times.
        for _ in 0..10 {
            state.update(nonce, key);
        }

        state
    }

    #[cfg(test)]
    pub fn ad(&mut self, ad: &[u8]) {
        let mut xi = [0u8; BLOCK_LEN];

        // Process whole blocks of associated data.
        let mut chunks = ad.chunks_exact(BLOCK_LEN);
        for chunk in chunks.by_ref() {
            xi.copy_from_slice(chunk);
            self.absorb(&xi);
        }

        // Process the remainder of the associated data, if any.
        let chunk = chunks.remainder();
        if !chunk.is_empty() {
            xi.fill(0);
            xi[..chunk.len()].copy_from_slice(chunk);
            self.absorb(&xi);
        }

        self.ad_len += ad.len() as u64;
    }

    pub fn prf(&mut self, out: &mut [u8]) {
        let mut ci = [0u8; BLOCK_LEN];

        // Process whole blocks of output.
        let mut chunks = out.chunks_exact_mut(BLOCK_LEN);
        for chunk in chunks.by_ref() {
            self.enc_zeroes(&mut ci);
            chunk.copy_from_slice(&ci);
        }

        // Process the remainder of the output, if any.
        let chunk = chunks.into_remainder();
        if !chunk.is_empty() {
            self.enc_zeroes(&mut ci);
            chunk.copy_from_slice(&ci[..chunk.len()]);
        }

        self.mc_len += out.len() as u64;
    }

    pub fn encrypt(&mut self, in_out: &mut [u8]) {
        let mut xi = [0u8; BLOCK_LEN];
        let mut ci = [0u8; BLOCK_LEN];

        // Process whole blocks of plaintext.
        let mut chunks = in_out.chunks_exact_mut(BLOCK_LEN);
        for chunk in chunks.by_ref() {
            xi.copy_from_slice(chunk);
            self.enc(&mut ci, &xi);
            chunk.copy_from_slice(&ci);
        }

        // Process the remainder of the plaintext, if any.
        let chunk = chunks.into_remainder();
        if !chunk.is_empty() {
            xi.fill(0);
            xi[..chunk.len()].copy_from_slice(chunk);
            self.enc(&mut ci, &xi);
            chunk.copy_from_slice(&ci[..chunk.len()]);
        }

        self.mc_len += in_out.len() as u64;
    }

    pub fn decrypt(&mut self, in_out: &mut [u8]) {
        let mut ci = [0u8; BLOCK_LEN];
        let mut xi = [0u8; BLOCK_LEN];

        // Process whole blocks of ciphertext.
        let mut chunks = in_out.chunks_exact_mut(BLOCK_LEN);
        for chunk in chunks.by_ref() {
            ci.copy_from_slice(chunk);
            self.dec(&mut xi, &ci);
            chunk.copy_from_slice(&xi);
        }

        // Process the remainder of the ciphertext, if any.
        let cn = chunks.into_remainder();
        if !cn.is_empty() {
            self.dec_partial(&mut xi, cn);
            cn.copy_from_slice(&xi[..cn.len()]);
        }

        self.mc_len += in_out.len() as u64;
    }

    #[cfg(test)]
    fn absorb(&mut self, ai: &[u8; BLOCK_LEN]) {
        // Load the input blocks.
        let (ai0, xi1) = load_2x(ai);

        // Update the cipher state with the two blocks.
        self.update(ai0, xi1);
    }

    fn enc_zeroes(&mut self, ci: &mut [u8; BLOCK_LEN]) {
        // Generate two blocks of keystream.
        let z0 = xor3(self.blocks[6], self.blocks[1], and(self.blocks[2], self.blocks[3]));
        let z1 = xor3(self.blocks[2], self.blocks[5], and(self.blocks[6], self.blocks[7]));

        // Store the keystream blocks in the output.
        store_2x(ci, z0, z1);

        // Update the cipher state as if two all-zero blocks were encrypted.
        let xi = zero();
        self.update(xi, xi);
    }

    fn enc(&mut self, ci: &mut [u8; BLOCK_LEN], xi: &[u8; BLOCK_LEN]) {
        // Generate two blocks of keystream.
        let z0 = xor3(self.blocks[6], self.blocks[1], and(self.blocks[2], self.blocks[3]));
        let z1 = xor3(self.blocks[2], self.blocks[5], and(self.blocks[6], self.blocks[7]));

        // Load the plaintext blocks.
        let (xi0, xi1) = load_2x(xi);

        // XOR the plaintext blocks with the keystream to produce ciphertext blocks.
        let ci0 = xor(xi0, z0);
        let ci1 = xor(xi1, z1);

        // Store ciphertext blocks in the output slice.
        store_2x(ci, ci0, ci1);

        // Update the state with the plaintext blocks.
        self.update(xi0, xi1);
    }

    fn dec(&mut self, xi: &mut [u8; BLOCK_LEN], ci: &[u8; BLOCK_LEN]) {
        // Generate two blocks of keystream.
        let z0 = xor3(self.blocks[6], self.blocks[1], and(self.blocks[2], self.blocks[3]));
        let z1 = xor3(self.blocks[2], self.blocks[5], and(self.blocks[6], self.blocks[7]));

        // Load the ciphertext blocks.
        let (ci0, ci1) = load_2x(ci);

        // XOR the ciphertext blocks with the keystream to produce plaintext blocks.
        let xi0 = xor(z0, ci0);
        let xi1 = xor(z1, ci1);

        // Store plaintext blocks in the output slice.
        store_2x(xi, xi0, xi1);

        // Update the state with the plaintext blocks.
        self.update(xi0, xi1);
    }

    fn dec_partial(&mut self, xn: &mut [u8; BLOCK_LEN], cn: &[u8]) {
        // Pad the ciphertext with zeros to form two blocks.
        let mut cn_padded = [0u8; BLOCK_LEN];
        cn_padded[..cn.len()].copy_from_slice(cn);

        // Generate two blocks of keystream.
        let z0 = xor3(self.blocks[6], self.blocks[1], and(self.blocks[2], self.blocks[3]));
        let z1 = xor3(self.blocks[2], self.blocks[5], and(self.blocks[6], self.blocks[7]));

        // Load the padded ciphertext blocks.
        let (cn0, cn1) = load_2x(&cn_padded);

        // XOR the ciphertext blocks with the keystream to produce padded plaintext blocks.
        let xn0 = xor(cn0, z0);
        let xn1 = xor(cn1, z1);

        // Store plaintext blocks in the output slice and zero out the padding.
        store_2x(xn, xn0, xn1);
        xn[cn.len()..].fill(0);

        // Re-split the padding-less plaintext output, load it into blocks, and use it to update the
        // state.
        let (xn0, xn1) = load_2x(xn);
        self.update(xn0, xn1);
    }

    pub fn finalize(&mut self) -> [u8; BLOCK_LEN] {
        // Create a block from the associated data and message lengths, in bits, XOR it with the 3rd
        // state block and update the state with that value.
        let t = xor(load_64x2(self.ad_len * 8, self.mc_len * 8), self.blocks[2]);
        for _ in 0..7 {
            self.update(t, t);
        }

        // Generate a long tag.
        let mut tag = [0u8; BLOCK_LEN];
        let a = xor(xor3(self.blocks[0], self.blocks[1], self.blocks[2]), self.blocks[3]);
        let b = xor(xor3(self.blocks[4], self.blocks[5], self.blocks[6]), self.blocks[7]);
        store_2x(&mut tag, a, b);
        tag
    }

    fn update(&mut self, m0: AesBlock, m1: AesBlock) {
        // Make a temporary copy of the last state block.
        let block7 = self.blocks[7];

        // Perform the AES rounds in place.
        self.blocks[7] = enc(self.blocks[6], self.blocks[7]);
        self.blocks[6] = enc(self.blocks[5], self.blocks[6]);
        self.blocks[5] = enc(self.blocks[4], self.blocks[5]);
        self.blocks[4] = enc(self.blocks[3], self.blocks[4]);
        self.blocks[3] = enc(self.blocks[2], self.blocks[3]);
        self.blocks[2] = enc(self.blocks[1], self.blocks[2]);
        self.blocks[1] = enc(self.blocks[0], self.blocks[1]);
        self.blocks[0] = enc(block7, self.blocks[0]);

        // XOR blocks 0 and 4 with the two message blocks.
        self.blocks[0] = xor(self.blocks[0], m0);
        self.blocks[4] = xor(self.blocks[4], m1);
    }
}

/// Load two AES blocks from the given slice.
#[inline]
fn load_2x(bytes: &[u8; BLOCK_LEN]) -> (AesBlock, AesBlock) {
    let (hi, lo) = bytes.split_at(AES_BLOCK_LEN);
    (load(hi), load(lo))
}

/// Store two AES blocks in the given slice.
#[inline]
fn store_2x(bytes: &mut [u8; BLOCK_LEN], hi: AesBlock, lo: AesBlock) {
    let (b_hi, b_lo) = bytes.split_at_mut(AES_BLOCK_LEN);
    store(b_hi, hi);
    store(b_lo, lo);
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    use expect_test::expect;
    use hex_literal::hex;
    use proptest::collection::vec;
    use proptest::prelude::*;

    fn encrypt(key: &[u8; 16], nonce: &[u8; 16], mc: &mut [u8], ad: &[u8]) -> [u8; 32] {
        let mut state = Aegis128L::new(key, nonce);
        state.ad(ad);
        state.encrypt(mc);
        state.finalize()
    }

    fn decrypt(key: &[u8; 16], nonce: &[u8; 16], mc: &mut [u8], ad: &[u8]) -> [u8; 32] {
        let mut state = Aegis128L::new(key, nonce);
        state.ad(ad);
        state.decrypt(mc);
        state.finalize()
    }

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

    // from https://www.ietf.org/archive/id/draft-irtf-cfrg-aegis-aead-04.html

    #[test]
    fn aes_round_test_vector() {
        let a = load(&hex!("000102030405060708090a0b0c0d0e0f"));
        let b = load(&hex!("101112131415161718191a1b1c1d1e1f"));
        let out = enc(a, b);
        let mut c = [0u8; 16];
        store(&mut c, out);

        expect!["7a7b4e5638782546a8c0477a3b813f43"].assert_eq(&hex::encode(c));
    }

    #[test]
    fn update_test_vector() {
        let mut state = Aegis128L {
            blocks: [
                load(&hex!("9b7e60b24cc873ea894ecc07911049a3")),
                load(&hex!("330be08f35300faa2ebf9a7b0d274658")),
                load(&hex!("7bbd5bd2b049f7b9b515cf26fbe7756c")),
                load(&hex!("c35a00f55ea86c3886ec5e928f87db18")),
                load(&hex!("9ebccafce87cab446396c4334592c91f")),
                load(&hex!("58d83e31f256371e60fc6bb257114601")),
                load(&hex!("1639b56ea322c88568a176585bc915de")),
                load(&hex!("640818ffb57dc0fbc2e72ae93457e39a")),
            ],
            ad_len: 0,
            mc_len: 0,
        };

        let d1 = load(&hex!("033e6975b94816879e42917650955aa0"));
        let d2 = load(&hex!("033e6975b94816879e42917650955aa0"));

        state.update(d1, d2);

        let mut blocks = [[0u8; 16]; 8];
        store(&mut blocks[0], state.blocks[0]);
        store(&mut blocks[1], state.blocks[1]);
        store(&mut blocks[2], state.blocks[2]);
        store(&mut blocks[3], state.blocks[3]);
        store(&mut blocks[4], state.blocks[4]);
        store(&mut blocks[5], state.blocks[5]);
        store(&mut blocks[6], state.blocks[6]);
        store(&mut blocks[7], state.blocks[7]);

        expect!["596ab773e4433ca0127c73f60536769d"].assert_eq(&hex::encode(blocks[0]));
        expect!["790394041a3d26ab697bde865014652d"].assert_eq(&hex::encode(blocks[1]));
        expect!["38cf49e4b65248acd533041b64dd0611"].assert_eq(&hex::encode(blocks[2]));
        expect!["16d8e58748f437bfff1797f780337cee"].assert_eq(&hex::encode(blocks[3]));
        expect!["69761320f7dd738b281cc9f335ac2f5a"].assert_eq(&hex::encode(blocks[4]));
        expect!["a21746bb193a569e331e1aa985d0d729"].assert_eq(&hex::encode(blocks[5]));
        expect!["09d714e6fcf9177a8ed1cde7e3d259a6"].assert_eq(&hex::encode(blocks[6]));
        expect!["61279ba73167f0ab76f0a11bf203bdff"].assert_eq(&hex::encode(blocks[7]));
    }

    #[test]
    fn test_vector_1() {
        let key = hex!("10010000000000000000000000000000");
        let nonce = hex!("10000200000000000000000000000000");
        let ad = hex!("");
        let (ct, long_tag) = {
            let mut msg = hex!("00000000000000000000000000000000");
            let tag = encrypt(&key, &nonce, &mut msg, &ad);
            (msg, tag)
        };

        expect!["c1c0e58bd913006feba00f4b3cc3594e"].assert_eq(&hex::encode(ct));
        expect!["25835bfbb21632176cf03840687cb968cace4617af1bd0f7d064c639a5c79ee4"]
            .assert_eq(&hex::encode(long_tag));
    }

    #[test]
    fn test_vector_2() {
        let key = hex!("10010000000000000000000000000000");
        let nonce = hex!("10000200000000000000000000000000");
        let ad = hex!("");
        let (ct, long_tag) = {
            let mut msg = [0u8; 0];
            let tag = encrypt(&key, &nonce, &mut msg, &ad);
            (msg, tag)
        };

        assert_eq!([0u8; 0], ct);
        expect!["1360dc9db8ae42455f6e5b6a9d488ea4f2184c4e12120249335c4ee84bafe25d"]
            .assert_eq(&hex::encode(long_tag));
    }

    #[test]
    fn test_vector_3() {
        let key = hex!("10010000000000000000000000000000");
        let nonce = hex!("10000200000000000000000000000000");
        let ad = hex!("0001020304050607");
        let (ct, long_tag) = {
            let mut msg = hex!(
                "000102030405060708090a0b0c0d0e0f"
                "101112131415161718191a1b1c1d1e1f"
            );
            let tag = encrypt(&key, &nonce, &mut msg, &ad);
            (msg, tag)
        };

        assert_eq!(
            hex!(
                "79d94593d8c2119d7e8fd9b8fc77845c"
                "5c077a05b2528b6ac54b563aed8efe84"
            ),
            ct
        );
        expect!["022cb796fe7e0ae1197525ff67e309484cfbab6528ddef89f17d74ef8ecd82b3"]
            .assert_eq(&hex::encode(long_tag));
    }

    #[test]
    fn test_vector_4() {
        let key = hex!("10010000000000000000000000000000");
        let nonce = hex!("10000200000000000000000000000000");
        let ad = hex!("0001020304050607");
        let (ct, long_tag) = {
            let mut msg = hex!("000102030405060708090a0b0c0d");
            let tag = encrypt(&key, &nonce, &mut msg, &ad);
            (msg, tag)
        };

        expect!["79d94593d8c2119d7e8fd9b8fc77"].assert_eq(&hex::encode(ct));
        expect!["86f1b80bfb463aba711d15405d094baf4a55a15dbfec81a76f35ed0b9c8b04ac"]
            .assert_eq(&hex::encode(long_tag));
    }

    #[test]
    fn test_vector_5() {
        let key = hex!("10010000000000000000000000000000");
        let nonce = hex!("10000200000000000000000000000000");
        let ad = hex!(
            "000102030405060708090a0b0c0d0e0f"
            "101112131415161718191a1b1c1d1e1f"
            "20212223242526272829"
        );
        let (ct, long_tag) = {
            let mut msg = hex!(
                "101112131415161718191a1b1c1d1e1f"
                "202122232425262728292a2b2c2d2e2f"
                "3031323334353637"
            );
            let tag = encrypt(&key, &nonce, &mut msg, &ad);
            (msg, tag)
        };

        assert_eq!(
            hex!(
                "b31052ad1cca4e291abcf2df3502e6bd"
                "b1bfd6db36798be3607b1f94d34478aa"
                "7ede7f7a990fec10"
            ),
            ct
        );
        expect!["b91e2947a33da8bee89b6794e647baf0fc835ff574aca3fc27c33be0db2aff98"]
            .assert_eq(&hex::encode(long_tag));
    }

    #[test]
    fn test_vector_6() {
        let key = hex!("10000200000000000000000000000000");
        let nonce = hex!("10010000000000000000000000000000");
        let ad = hex!("0001020304050607");
        let mut ct = hex!("79d94593d8c2119d7e8fd9b8fc77");
        let long_tag = decrypt(&key, &nonce, &mut ct, &ad);

        assert_ne!(
            "86f1b80bfb463aba711d15405d094baf4a55a15dbfec81a76f35ed0b9c8b04ac",
            hex::encode(long_tag)
        );
    }

    #[test]
    fn test_vector_7() {
        let key = hex!("10010000000000000000000000000000");
        let nonce = hex!("10000200000000000000000000000000");
        let ad = hex!("0001020304050607");
        let mut ct = hex!("79d94593d8c2119d7e8fd9b8fc78");
        let long_tag = decrypt(&key, &nonce, &mut ct, &ad);

        assert_ne!(
            "86f1b80bfb463aba711d15405d094baf4a55a15dbfec81a76f35ed0b9c8b04ac",
            hex::encode(long_tag)
        );
    }

    #[test]
    fn test_vector_8() {
        let key = hex!("10010000000000000000000000000000");
        let nonce = hex!("10000200000000000000000000000000");
        let ad = hex!("0001020304050608");
        let mut ct = hex!("79d94593d8c2119d7e8fd9b8fc77");
        let long_tag = decrypt(&key, &nonce, &mut ct, &ad);

        assert_ne!(
            "86f1b80bfb463aba711d15405d094baf4a55a15dbfec81a76f35ed0b9c8b04ac",
            hex::encode(long_tag)
        );
    }

    #[test]
    fn test_vector_9() {
        let key = hex!("10010000000000000000000000000000");
        let nonce = hex!("10000200000000000000000000000000");
        let ad = hex!("0001020304050607");
        let mut ct = hex!("79d94593d8c2119d7e8fd9b8fc77");
        let long_tag = decrypt(&key, &nonce, &mut ct, &ad);

        assert_ne!(
            "86f1b80bfb463aba711d15405d094baf4a55a15dbfec81a76f35ed0b9c8b04ad",
            hex::encode(long_tag)
        );
    }

    proptest! {
        #[test]
        fn round_trip(
            k: [u8; 16],
            n: [u8; 16],
            ad in vec(any::<u8>(), 0..200),
            msg in vec(any::<u8>(), 0..200)) {

            let mut ct = msg.clone();
            let tag_e = encrypt(&k, &n, &mut ct, &ad);
            let tag_d = decrypt(&k, &n, &mut ct, &ad);

            prop_assert_eq!(msg, ct, "invalid plaintext");
            prop_assert_eq!(tag_e, tag_d, "invalid tag");
        }
    }
}
