use crate::intrinsics::*;

/// An AEGIS-128L instance.
#[derive(Debug, Clone)]
pub struct Aegis128L {
    state: [AesBlock; 8],
    ad_len: u64,
    msg_len: u64,
}

impl Aegis128L {
    /// Creates a new AEGIS-128L instance with the given key and nonce.
    pub fn new(key: &[u8], nonce: &[u8]) -> Self {
        // Initialize constants.
        let (c0, c1) = load_2x(&C);

        // Initialize key and nonce blocks.
        let key = load(key);
        let nonce = load(nonce);

        // Initialize cipher state.
        let key_nonce = xor(key, nonce);
        let key_c0 = xor(key, c0);
        let mut state = [key_nonce, c1, c0, c1, key_nonce, key_c0, xor(key, c1), key_c0];

        // Update the state with the nonce and key 10 times.
        for _ in 0..10 {
            update(&mut state, nonce, key);
        }

        Aegis128L { state, ad_len: 0, msg_len: 0 }
    }

    /// Processes the given authenticated data.
    #[cfg(all(test, feature = "std"))]
    pub fn ad(&mut self, ad: &[u8]) {
        // Process whole blocks of associated data.
        let mut chunks = ad.chunks_exact(BLOCK_LEN);
        for chunk in chunks.by_ref() {
            self.absorb(chunk);
        }

        // Process the remainder of the associated data, if any.
        let chunk = chunks.remainder();
        if !chunk.is_empty() {
            // Pad the input to two blocks.
            let mut tmp = [0u8; BLOCK_LEN];
            tmp[..chunk.len()].copy_from_slice(chunk);
            self.absorb(&tmp);
        }

        self.ad_len += ad.len() as u64;
    }

    /// Encrypts the given slice in place.
    pub fn encrypt(&mut self, in_out: &mut [u8]) {
        // Process whole blocks of plaintext.
        let mut chunks = in_out.chunks_exact_mut(BLOCK_LEN);
        for chunk in chunks.by_ref() {
            self.enc(chunk);
        }

        // Process the remainder of the plaintext, if any.
        let chunk = chunks.into_remainder();
        if !chunk.is_empty() {
            let mut tmp = [0u8; BLOCK_LEN];
            tmp[..chunk.len()].copy_from_slice(chunk);
            self.enc(&mut tmp);
            chunk.copy_from_slice(&tmp[..chunk.len()]);
        }

        self.msg_len += in_out.len() as u64;
    }

    /// Decrypts the given slice in place.
    pub fn decrypt(&mut self, in_out: &mut [u8]) {
        // Process whole blocks of ciphertext.
        let mut chunks = in_out.chunks_exact_mut(BLOCK_LEN);
        for chunk in chunks.by_ref() {
            self.dec(chunk);
        }

        // Process the remainder of the ciphertext, if any.
        let cn = chunks.into_remainder();
        if !cn.is_empty() {
            self.dec_partial(cn);
        }

        self.msg_len += in_out.len() as u64;
    }

    /// Finalizes the cipher state into a pair of 128-bit and 256-bit authentication tags.
    pub fn finalize(mut self) -> ([u8; 16], [u8; 32]) {
        let ad_len_bits = self.ad_len * 8;
        let msg_len_bits = self.msg_len * 8;

        // Create a block from the associated data and message lengths, in bits, XOR it with the 3rd
        // state block and update the state with that value.
        let t = xor(load_64x2(ad_len_bits, msg_len_bits), self.state[2]);
        for _ in 0..7 {
            update(&mut self.state, t, t);
        }

        // Generate both 128-bit and 256-bit tags, re-using values where possible.
        let mut tag128 = [0u8; 16];
        let mut tag256 = [0u8; 32];
        let a = xor(xor3(self.state[0], self.state[1], self.state[2]), self.state[3]);
        let b = xor3(self.state[4], self.state[5], self.state[6]);
        store(&mut tag128, xor(a, b));
        store_2x(&mut tag256, a, xor(b, self.state[7]));

        (tag128, tag256)
    }

    #[cfg(all(test, feature = "std"))]
    fn absorb(&mut self, ai: &[u8]) {
        // Load the input blocks.
        let (t0, t1) = load_2x(ai);

        // Update the cipher state with the two blocks.
        update(&mut self.state, t0, t1);
    }

    fn enc(&mut self, xi: &mut [u8]) {
        // Generate two blocks of keystream.
        let z0 = xor3(self.state[6], self.state[1], and(self.state[2], self.state[3]));
        let z1 = xor3(self.state[2], self.state[5], and(self.state[6], self.state[7]));

        // Load the plaintext blocks.
        let (t0, t1) = load_2x(xi);

        // XOR the plaintext blocks with the keystream to produce ciphertext blocks.
        let out0 = xor(t0, z0);
        let out1 = xor(t1, z1);

        // Update the state with the plaintext blocks.
        update(&mut self.state, t0, t1);

        // Store ciphertext blocks in the output slice.
        store_2x(xi, out0, out1);
    }

    fn dec(&mut self, ci: &mut [u8]) {
        // Generate two blocks of keystream.
        let z0 = xor3(self.state[6], self.state[1], and(self.state[2], self.state[3]));
        let z1 = xor3(self.state[2], self.state[5], and(self.state[6], self.state[7]));

        // Load the ciphertext blocks.
        let (t0, t1) = load_2x(ci);

        // XOR the ciphertext blocks with the keystream to produce plaintext blocks.
        let out0 = xor(z0, t0);
        let out1 = xor(z1, t1);

        // Update the state with the plaintext blocks.
        update(&mut self.state, out0, out1);

        // Store plaintext blocks in the output slice.
        store_2x(ci, out0, out1);
    }

    fn dec_partial(&mut self, xn: &mut [u8]) {
        // Generate two blocks of keystream.
        let z0 = xor3(self.state[6], self.state[1], and(self.state[2], self.state[3]));
        let z1 = xor3(self.state[2], self.state[5], and(self.state[6], self.state[7]));

        // Pad the ciphertext with zeros to form two blocks.
        let mut tmp = [0u8; BLOCK_LEN];
        tmp[..xn.len()].copy_from_slice(xn);
        let (t0, t1) = load_2x(&tmp);

        // XOR the ciphertext blocks with the keystream to produce padded plaintext blocks.
        let out0 = xor(t0, z0);
        let out1 = xor(t1, z1);

        // Store the decrypted plaintext blocks in the output slice.
        store_2x(&mut tmp, out0, out1);
        xn.copy_from_slice(&tmp[..xn.len()]);

        // Pad the plaintext with zeros to form two blocks.
        tmp[xn.len()..].fill(0);
        let (v0, v1) = load_2x(&tmp);

        // Update the state with the padded plaintext blocks.
        update(&mut self.state, v0, v1);
    }
}

impl Drop for Aegis128L {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            use zeroize::Zeroize;
            for s in self.state.iter_mut() {
                s.zeroize();
            }
            self.ad_len.zeroize();
            self.msg_len.zeroize();
        }
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::ZeroizeOnDrop for Aegis128L {}

/// The core AEGIS-128L update function.
fn update(state: &mut [AesBlock; 8], m0: AesBlock, m1: AesBlock) {
    // Make a temporary copy of the last state block.
    let state7 = state[7];

    // Perform the AES rounds in place.
    state[7] = enc(state[6], state[7]);
    state[6] = enc(state[5], state[6]);
    state[5] = enc(state[4], state[5]);
    state[4] = enc(state[3], state[4]);
    state[3] = enc(state[2], state[3]);
    state[2] = enc(state[1], state[2]);
    state[1] = enc(state[0], state[1]);
    state[0] = enc(state7, state[0]);

    // XOR blocks 0 and 4 with the two message blocks.
    state[0] = xor(state[0], m0);
    state[4] = xor(state[4], m1);
}

/// The length of an AEGIS-128L block.
const BLOCK_LEN: usize = 32;

/// Initialization constants `C0` and `C1`.
const C: [u8; 32] = [
    0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62,
    0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd,
];

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    use expect_test::expect;
    use hex_literal::hex;
    use wycheproof::{
        aead::{TestName, TestSet},
        TestResult,
    };

    fn encrypt(key: &[u8; 16], nonce: &[u8; 16], mc: &mut [u8], ad: &[u8]) -> ([u8; 16], [u8; 32]) {
        let mut state = Aegis128L::new(key, nonce);
        state.ad(ad);
        state.encrypt(mc);
        state.finalize()
    }

    fn decrypt(key: &[u8; 16], nonce: &[u8; 16], mc: &mut [u8], ad: &[u8]) -> ([u8; 16], [u8; 32]) {
        let mut state = Aegis128L::new(key, nonce);
        state.ad(ad);
        state.decrypt(mc);
        state.finalize()
    }

    #[test]
    fn update_test_vector() {
        let mut state = [
            load(&hex!("9b7e60b24cc873ea894ecc07911049a3")),
            load(&hex!("330be08f35300faa2ebf9a7b0d274658")),
            load(&hex!("7bbd5bd2b049f7b9b515cf26fbe7756c")),
            load(&hex!("c35a00f55ea86c3886ec5e928f87db18")),
            load(&hex!("9ebccafce87cab446396c4334592c91f")),
            load(&hex!("58d83e31f256371e60fc6bb257114601")),
            load(&hex!("1639b56ea322c88568a176585bc915de")),
            load(&hex!("640818ffb57dc0fbc2e72ae93457e39a")),
        ];

        let d1 = load(&hex!("033e6975b94816879e42917650955aa0"));
        let d2 = load(&hex!("033e6975b94816879e42917650955aa0"));

        update(&mut state, d1, d2);

        let mut blocks = [[0u8; 16]; 8];
        store(&mut blocks[0], state[0]);
        store(&mut blocks[1], state[1]);
        store(&mut blocks[2], state[2]);
        store(&mut blocks[3], state[3]);
        store(&mut blocks[4], state[4]);
        store(&mut blocks[5], state[5]);
        store(&mut blocks[6], state[6]);
        store(&mut blocks[7], state[7]);

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
        let (ct, (tag128, tag256)) = {
            let mut msg = hex!("00000000000000000000000000000000");
            let tags = encrypt(&key, &nonce, &mut msg, &ad);
            (msg, tags)
        };

        expect!["c1c0e58bd913006feba00f4b3cc3594e"].assert_eq(&hex::encode(ct));
        expect!["abe0ece80c24868a226a35d16bdae37a"].assert_eq(&hex::encode(tag128));
        expect!["25835bfbb21632176cf03840687cb968cace4617af1bd0f7d064c639a5c79ee4"]
            .assert_eq(&hex::encode(tag256));
    }

    #[test]
    fn test_vector_2() {
        let key = hex!("10010000000000000000000000000000");
        let nonce = hex!("10000200000000000000000000000000");
        let ad = hex!("");
        let (ct, (tag128, tag256)) = {
            let mut msg = [0u8; 0];
            let tags = encrypt(&key, &nonce, &mut msg, &ad);
            (msg, tags)
        };

        assert_eq!([0u8; 0], ct);
        expect!["c2b879a67def9d74e6c14f708bbcc9b4"].assert_eq(&hex::encode(tag128));
        expect!["1360dc9db8ae42455f6e5b6a9d488ea4f2184c4e12120249335c4ee84bafe25d"]
            .assert_eq(&hex::encode(tag256));
    }

    #[test]
    fn test_vector_3() {
        let key = hex!("10010000000000000000000000000000");
        let nonce = hex!("10000200000000000000000000000000");
        let ad = hex!("0001020304050607");
        let (ct, (tag128, tag256)) = {
            let mut msg = hex!(
                "000102030405060708090a0b0c0d0e0f"
                "101112131415161718191a1b1c1d1e1f"
            );
            let tags = encrypt(&key, &nonce, &mut msg, &ad);
            (msg, tags)
        };

        assert_eq!(
            hex!(
                "79d94593d8c2119d7e8fd9b8fc77845c"
                "5c077a05b2528b6ac54b563aed8efe84"
            ),
            ct
        );
        expect!["cc6f3372f6aa1bb82388d695c3962d9a"].assert_eq(&hex::encode(tag128));
        expect!["022cb796fe7e0ae1197525ff67e309484cfbab6528ddef89f17d74ef8ecd82b3"]
            .assert_eq(&hex::encode(tag256));
    }

    #[test]
    fn test_vector_4() {
        let key = hex!("10010000000000000000000000000000");
        let nonce = hex!("10000200000000000000000000000000");
        let ad = hex!("0001020304050607");
        let (ct, (tag128, tag256)) = {
            let mut msg = hex!("000102030405060708090a0b0c0d");
            let tags = encrypt(&key, &nonce, &mut msg, &ad);
            (msg, tags)
        };

        expect!["79d94593d8c2119d7e8fd9b8fc77"].assert_eq(&hex::encode(ct));
        expect!["5c04b3dba849b2701effbe32c7f0fab7"].assert_eq(&hex::encode(tag128));
        expect!["86f1b80bfb463aba711d15405d094baf4a55a15dbfec81a76f35ed0b9c8b04ac"]
            .assert_eq(&hex::encode(tag256));
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
        let (ct, (tag128, tag256)) = {
            let mut msg = hex!(
                "101112131415161718191a1b1c1d1e1f"
                "202122232425262728292a2b2c2d2e2f"
                "3031323334353637"
            );
            let tags = encrypt(&key, &nonce, &mut msg, &ad);
            (msg, tags)
        };

        assert_eq!(
            hex!(
                "b31052ad1cca4e291abcf2df3502e6bd"
                "b1bfd6db36798be3607b1f94d34478aa"
                "7ede7f7a990fec10"
            ),
            ct
        );
        expect!["7542a745733014f9474417b337399507"].assert_eq(&hex::encode(tag128));
        expect!["b91e2947a33da8bee89b6794e647baf0fc835ff574aca3fc27c33be0db2aff98"]
            .assert_eq(&hex::encode(tag256));
    }

    #[test]
    fn test_vector_6() {
        let key = hex!("10000200000000000000000000000000");
        let nonce = hex!("10010000000000000000000000000000");
        let ad = hex!("0001020304050607");
        let mut ct = hex!("79d94593d8c2119d7e8fd9b8fc77");
        let (tag128, tag256) = decrypt(&key, &nonce, &mut ct, &ad);

        assert_ne!("5c04b3dba849b2701effbe32c7f0fab7", hex::encode(tag128));
        assert_ne!(
            "86f1b80bfb463aba711d15405d094baf4a55a15dbfec81a76f35ed0b9c8b04ac",
            hex::encode(tag256)
        );
    }

    #[test]
    fn test_vector_7() {
        let key = hex!("10010000000000000000000000000000");
        let nonce = hex!("10000200000000000000000000000000");
        let ad = hex!("0001020304050607");
        let mut ct = hex!("79d94593d8c2119d7e8fd9b8fc78");
        let (tag128, tag256) = decrypt(&key, &nonce, &mut ct, &ad);

        assert_ne!("5c04b3dba849b2701effbe32c7f0fab7", hex::encode(tag128));
        assert_ne!(
            "86f1b80bfb463aba711d15405d094baf4a55a15dbfec81a76f35ed0b9c8b04ac",
            hex::encode(tag256)
        );
    }

    #[test]
    fn test_vector_8() {
        let key = hex!("10010000000000000000000000000000");
        let nonce = hex!("10000200000000000000000000000000");
        let ad = hex!("0001020304050608");
        let mut ct = hex!("79d94593d8c2119d7e8fd9b8fc77");
        let (tag128, tag256) = decrypt(&key, &nonce, &mut ct, &ad);

        assert_ne!("5c04b3dba849b2701effbe32c7f0fab7", hex::encode(tag128));
        assert_ne!(
            "86f1b80bfb463aba711d15405d094baf4a55a15dbfec81a76f35ed0b9c8b04ac",
            hex::encode(tag256)
        );
    }

    #[test]
    fn test_vector_9() {
        let key = hex!("10010000000000000000000000000000");
        let nonce = hex!("10000200000000000000000000000000");
        let ad = hex!("0001020304050607");
        let mut ct = hex!("79d94593d8c2119d7e8fd9b8fc77");
        let (tag128, tag256) = decrypt(&key, &nonce, &mut ct, &ad);

        assert_ne!("6c04b3dba849b2701effbe32c7f0fab8", hex::encode(tag128));
        assert_ne!(
            "86f1b80bfb463aba711d15405d094baf4a55a15dbfec81a76f35ed0b9c8b04ad",
            hex::encode(tag256)
        );
    }

    #[test]
    fn round_trip() {
        bolero::check!().with_type::<([u8; 16], [u8; 16], Vec<u8>, Vec<u8>)>().for_each(
            |(k, n, ad, msg)| {
                let mut ct = msg.clone();
                let tag_e = encrypt(k, n, &mut ct, ad);
                let tag_d = decrypt(k, n, &mut ct, ad);

                assert_eq!(msg, &ct);
                assert_eq!(tag_e, tag_d);
            },
        );
    }

    #[test]
    fn interop() {
        bolero::check!().with_type::<([u8; 16], [u8; 16], Vec<u8>, Vec<u8>)>().for_each(
            |(k, n, ad, msg)| {
                let mut ct = msg.clone();
                let (tag128, tag256) = encrypt(k, n, &mut ct, ad);

                let aegis16 = aegis::aegis128l::Aegis128L::<16>::new(k, n);
                let aegis32 = aegis::aegis128l::Aegis128L::<32>::new(k, n);

                assert_eq!(Ok(msg.to_vec()), aegis16.decrypt(&ct, &tag128, ad));
                assert_eq!(Ok(msg.to_vec()), aegis32.decrypt(&ct, &tag256, ad));
            },
        );
    }

    #[test]
    fn wycheproof() {
        let set = TestSet::load(TestName::Aegis128L).expect("should have AEGIS-128L test vectors");
        for group in set.test_groups {
            for test in group.tests {
                let mut ct = test.pt.to_vec();
                let (tag128, _tag256) = encrypt(
                    &test.key.as_ref().try_into().expect("should be 16 bytes"),
                    &test.nonce.as_ref().try_into().expect("should be 16 bytes"),
                    &mut ct,
                    &test.aad,
                );

                if test.result == TestResult::Valid {
                    assert_eq!(test.ct.as_ref(), &ct);
                    assert_eq!(test.tag.as_ref(), &tag128);
                } else {
                    assert_ne!(test.tag.as_ref(), &tag128);
                }
            }
        }
    }
}
