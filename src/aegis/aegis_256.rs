use crate::{intrinsics::*, Aegis};

/// An AEGIS-256 instance.
#[derive(Debug, Clone)]
pub struct Aegis256 {
    blocks: [AesBlock; 6],
    ad_len: u64,
    mc_len: u64,
}

impl Aegis256 {
    /// Creates a new AEGIS-256 instance with the given key and nonce.
    pub fn new(key: &[u8; 32], nonce: &[u8; 32]) -> Self {
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
        let (k0, k1) = load_2x(key);
        let (n0, n1) = load_2x(nonce);

        // Initialize cipher state.
        let k0_n0 = xor(k0, n0);
        let k1_n1 = xor(k1, n1);
        let mut state = Aegis256 {
            blocks: [k0_n0, k1_n1, c1, c0, xor(k0, c0), xor(k1, c1)],
            ad_len: 0,
            mc_len: 0,
        };

        // Update the state with the nonce and key 4 times.
        for _ in 0..4 {
            state.update(k0);
            state.update(k1);
            state.update(k0_n0);
            state.update(k1_n1);
        }

        state
    }

    /// Processes the given authenticated data.
    #[cfg(all(test, feature = "std"))]
    pub fn ad(&mut self, ad: &[u8]) {
        // Process whole blocks of associated data.
        let mut chunks = ad.chunks_exact(AES_BLOCK_LEN);
        for chunk in chunks.by_ref() {
            self.absorb(chunk);
        }

        // Process the remainder of the associated data, if any.
        let chunk = chunks.remainder();
        if !chunk.is_empty() {
            // Pad the input to a block.
            let mut tmp = [0u8; AES_BLOCK_LEN];
            tmp[..chunk.len()].copy_from_slice(chunk);
            self.absorb(&tmp);
        }

        self.ad_len += ad.len() as u64;
    }

    #[cfg(all(test, feature = "std"))]
    fn absorb(&mut self, ai: &[u8]) {
        // Load the input block.
        let ai = load(ai);

        // Update the cipher state with the blocks.
        self.update(ai);
    }

    fn enc(&mut self, in_out: &mut [u8]) {
        // Generate a block of keystream.
        let z = xor3(
            self.blocks[1],
            self.blocks[4],
            xor(self.blocks[5], and(self.blocks[2], self.blocks[3])),
        );

        // Load the plaintext.
        let xi = load(in_out);

        // XOR the plaintext block with the keystream to produce a ciphertext block.
        let ci = xor(xi, z);

        // Store ciphertext block in the output slice.
        store(in_out, ci);

        // Update the state with the plaintext block.
        self.update(xi);
    }

    fn dec(&mut self, in_out: &mut [u8]) {
        // Generate a block of keystream.
        let z = xor3(
            self.blocks[1],
            self.blocks[4],
            xor(self.blocks[5], and(self.blocks[2], self.blocks[3])),
        );

        // Load the ciphertext.
        let ci = load(in_out);

        // XOR the ciphertext block with the keystream to produce a plaintext block.
        let xi = xor(ci, z);

        // Store plaintext block in the output slice.
        store(in_out, xi);

        // Update the state with the plaintext block.
        self.update(xi);
    }

    fn dec_partial(&mut self, in_out: &mut [u8]) {
        let mut tmp = [0u8; AES_BLOCK_LEN];

        // Pad the ciphertext with zeros to form a block.
        tmp[..in_out.len()].copy_from_slice(in_out);
        let cn = load(&tmp);

        // Generate a block of keystream.
        let z = xor3(
            self.blocks[1],
            self.blocks[4],
            xor(self.blocks[5], and(self.blocks[2], self.blocks[3])),
        );

        // XOR the ciphertext block with the keystream to produce a plaintext block.
        let xn = xor(cn, z);

        // Store the decrypted plaintext block in the output slice.
        store(&mut tmp, xn);
        in_out.copy_from_slice(&tmp[..in_out.len()]);

        // Pad the plaintext with zeros to form a block and update the state with it.
        tmp[in_out.len()..].fill(0);
        let xn = load(&tmp);
        self.update(xn);
    }

    fn update(&mut self, m: AesBlock) {
        self.blocks = [
            enc(self.blocks[5], xor(self.blocks[0], m)),
            enc(self.blocks[0], self.blocks[1]),
            enc(self.blocks[1], self.blocks[2]),
            enc(self.blocks[2], self.blocks[3]),
            enc(self.blocks[3], self.blocks[4]),
            enc(self.blocks[4], self.blocks[5]),
        ];
    }
}

impl Aegis for Aegis256 {
    fn encrypt(&mut self, in_out: &mut [u8]) {
        // Process whole blocks of plaintext.
        let mut chunks = in_out.chunks_exact_mut(AES_BLOCK_LEN);
        for chunk in chunks.by_ref() {
            self.enc(chunk);
        }

        // Process the remainder of the plaintext, if any.
        let chunk = chunks.into_remainder();
        if !chunk.is_empty() {
            let mut tmp = [0u8; AES_BLOCK_LEN];
            tmp[..chunk.len()].copy_from_slice(chunk);
            self.enc(&mut tmp);
            chunk.copy_from_slice(&tmp[..chunk.len()]);
        }

        self.mc_len += in_out.len() as u64;
    }

    fn decrypt(&mut self, in_out: &mut [u8]) {
        // Process whole blocks of ciphertext.
        let mut chunks = in_out.chunks_exact_mut(AES_BLOCK_LEN);
        for chunk in chunks.by_ref() {
            self.dec(chunk);
        }

        // Process the remainder of the ciphertext, if any.
        let cn = chunks.into_remainder();
        if !cn.is_empty() {
            self.dec_partial(cn);
        }

        self.mc_len += in_out.len() as u64;
    }

    fn finalize(mut self) -> ([u8; AES_BLOCK_LEN], [u8; 32]) {
        // Create a block from the associated data and message lengths, in bits, XOR it with the 4th
        // state block and update the state with that value.
        let t = xor(load_64x2(self.ad_len * 8, self.mc_len * 8), self.blocks[3]);
        for _ in 0..7 {
            self.update(t);
        }

        // Generate both 128-bit and 256-bit tags, re-using values where possible.
        let mut tag128 = [0u8; AES_BLOCK_LEN];
        let mut tag256 = [0u8; 32];

        let a = xor3(self.blocks[0], self.blocks[1], self.blocks[2]);
        let b = xor3(self.blocks[3], self.blocks[4], self.blocks[5]);
        store(&mut tag128, xor(a, b));
        store_2x(&mut tag256, a, b);

        (tag128, tag256)
    }
}

#[cfg(test)]
mod tests {
    use expect_test::expect;
    use hex_literal::hex;
    use wycheproof::{
        aead::{TestName, TestSet},
        TestResult,
    };

    use super::*;

    fn encrypt(key: &[u8; 32], nonce: &[u8; 32], mc: &mut [u8], ad: &[u8]) -> ([u8; 16], [u8; 32]) {
        let mut state = Aegis256::new(key, nonce);
        state.ad(ad);
        state.encrypt(mc);
        state.finalize()
    }

    fn decrypt(key: &[u8; 32], nonce: &[u8; 32], mc: &mut [u8], ad: &[u8]) -> ([u8; 16], [u8; 32]) {
        let mut state = Aegis256::new(key, nonce);
        state.ad(ad);
        state.decrypt(mc);
        state.finalize()
    }

    #[test]
    fn update_test_vector() {
        let mut state = Aegis256 {
            blocks: [
                load(&hex!("1fa1207ed76c86f2c4bb40e8b395b43e")),
                load(&hex!("b44c375e6c1e1978db64bcd12e9e332f")),
                load(&hex!("0dab84bfa9f0226432ff630f233d4e5b")),
                load(&hex!("d7ef65c9b93e8ee60c75161407b066e7")),
                load(&hex!("a760bb3da073fbd92bdc24734b1f56fb")),
                load(&hex!("a828a18d6a964497ac6e7e53c5f55c73")),
            ],
            ad_len: 0,
            mc_len: 0,
        };

        let d1 = load(&hex!("b165617ed04ab738afb2612c6d18a1ec"));

        state.update(d1);

        let mut blocks = [[0u8; 16]; 6];
        store(&mut blocks[0], state.blocks[0]);
        store(&mut blocks[1], state.blocks[1]);
        store(&mut blocks[2], state.blocks[2]);
        store(&mut blocks[3], state.blocks[3]);
        store(&mut blocks[4], state.blocks[4]);
        store(&mut blocks[5], state.blocks[5]);

        expect!["e6bc643bae82dfa3d991b1b323839dcd"].assert_eq(&hex::encode(blocks[0]));
        expect!["648578232ba0f2f0a3677f617dc052c3"].assert_eq(&hex::encode(blocks[1]));
        expect!["ea788e0e572044a46059212dd007a789"].assert_eq(&hex::encode(blocks[2]));
        expect!["2f1498ae19b80da13fba698f088a8590"].assert_eq(&hex::encode(blocks[3]));
        expect!["a54c2ee95e8c2a2c3dae2ec743ae6b86"].assert_eq(&hex::encode(blocks[4]));
        expect!["a3240fceb68e32d5d114df1b5363ab67"].assert_eq(&hex::encode(blocks[5]));
    }

    #[test]
    fn test_vector_1() {
        let key = hex!("1001000000000000000000000000000000000000000000000000000000000000");
        let nonce = hex!("1000020000000000000000000000000000000000000000000000000000000000");
        let ad = hex!("");
        let (ct, (tag128, tag256)) = {
            let mut msg = hex!("00000000000000000000000000000000");
            let tags = encrypt(&key, &nonce, &mut msg, &ad);
            (msg, tags)
        };

        expect!["754fc3d8c973246dcc6d741412a4b236"].assert_eq(&hex::encode(ct));
        expect!["3fe91994768b332ed7f570a19ec5896e"].assert_eq(&hex::encode(tag128));
        expect!["1181a1d18091082bf0266f66297d167d2e68b845f61a3b0527d31fc7b7b89f13"]
            .assert_eq(&hex::encode(tag256));
    }

    #[test]
    fn test_vector_2() {
        let key = hex!("1001000000000000000000000000000000000000000000000000000000000000");
        let nonce = hex!("1000020000000000000000000000000000000000000000000000000000000000");
        let ad = hex!("");
        let (ct, (tag128, tag256)) = {
            let mut msg = hex!("");
            let tags = encrypt(&key, &nonce, &mut msg, &ad);
            (msg, tags)
        };

        expect![""].assert_eq(&hex::encode(ct));
        expect!["e3def978a0f054afd1e761d7553afba3"].assert_eq(&hex::encode(tag128));
        expect!["6a348c930adbd654896e1666aad67de989ea75ebaa2b82fb588977b1ffec864a"]
            .assert_eq(&hex::encode(tag256));
    }

    #[test]
    fn test_vector_3() {
        let key = hex!("1001000000000000000000000000000000000000000000000000000000000000");
        let nonce = hex!("1000020000000000000000000000000000000000000000000000000000000000");
        let ad = hex!("0001020304050607");
        let (ct, (tag128, tag256)) = {
            let mut msg = hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
            let tags = encrypt(&key, &nonce, &mut msg, &ad);
            (msg, tags)
        };

        expect!["f373079ed84b2709faee373584585d60accd191db310ef5d8b11833df9dec711"]
            .assert_eq(&hex::encode(ct));
        expect!["8d86f91ee606e9ff26a01b64ccbdd91d"].assert_eq(&hex::encode(tag128));
        expect!["b7d28d0c3c0ebd409fd22b44160503073a547412da0854bfb9723020dab8da1a"]
            .assert_eq(&hex::encode(tag256));
    }

    #[test]
    fn test_vector_4() {
        let key = hex!("1001000000000000000000000000000000000000000000000000000000000000");
        let nonce = hex!("1000020000000000000000000000000000000000000000000000000000000000");
        let ad = hex!("0001020304050607");
        let (ct, (tag128, tag256)) = {
            let mut msg = hex!("000102030405060708090a0b0c0d");
            let tags = encrypt(&key, &nonce, &mut msg, &ad);
            (msg, tags)
        };

        expect!["f373079ed84b2709faee37358458"].assert_eq(&hex::encode(ct));
        expect!["c60b9c2d33ceb058f96e6dd03c215652"].assert_eq(&hex::encode(tag128));
        expect!["8c1cc703c81281bee3f6d9966e14948b4a175b2efbdc31e61a98b4465235c2d9"]
            .assert_eq(&hex::encode(tag256));
    }

    #[test]
    fn test_vector_5() {
        let key = hex!("1001000000000000000000000000000000000000000000000000000000000000");
        let nonce = hex!("1000020000000000000000000000000000000000000000000000000000000000");
        let ad = hex!(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829"
        );
        let (ct, (tag128, tag256)) = {
            let mut msg = hex!(
                "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637"
            );
            let tags = encrypt(&key, &nonce, &mut msg, &ad);
            (msg, tags)
        };

        expect!["57754a7d09963e7c787583a2e7b859bb24fa1e04d49fd550b2511a358e3bca252a9b1b8b30cc4a67"]
            .assert_eq(&hex::encode(ct));
        expect!["ab8a7d53fd0e98d727accca94925e128"].assert_eq(&hex::encode(tag128));
        expect!["a3aca270c006094d71c20e6910b5161c0826df233d08919a566ec2c05990f734"]
            .assert_eq(&hex::encode(tag256));
    }

    #[test]
    fn test_vector_6() {
        let key = hex!("1000020000000000000000000000000000000000000000000000000000000000");
        let nonce = hex!("1001000000000000000000000000000000000000000000000000000000000000");
        let ad = hex!("0001020304050607");
        let mut ct = hex!("f373079ed84b2709faee37358458");
        let (tag128, tag256) = decrypt(&key, &nonce, &mut ct, &ad);

        assert_ne!("5c04b3dba849b2701effbe32c7f0fab7", hex::encode(tag128));
        assert_ne!(
            "86f1b80bfb463aba711d15405d094baf4a55a15dbfec81a76f35ed0b9c8b04ac",
            hex::encode(tag256)
        );
    }

    #[test]
    fn test_vector_7() {
        let key = hex!("1000020000000000000000000000000000000000000000000000000000000000");
        let nonce = hex!("1001000000000000000000000000000000000000000000000000000000000000");
        let ad = hex!("0001020304050607");
        let mut ct = hex!("f373079ed84b2709faee37358459");
        let (tag128, tag256) = decrypt(&key, &nonce, &mut ct, &ad);

        assert_ne!("c60b9c2d33ceb058f96e6dd03c215652", hex::encode(tag128));
        assert_ne!(
            "8c1cc703c81281bee3f6d9966e14948b4a175b2efbdc31e61a98b4465235c2d9",
            hex::encode(tag256)
        );
    }

    #[test]
    fn test_vector_8() {
        let key = hex!("1000020000000000000000000000000000000000000000000000000000000000");
        let nonce = hex!("1001000000000000000000000000000000000000000000000000000000000000");
        let ad = hex!("0001020304050608");
        let mut ct = hex!("f373079ed84b2709faee37358458");
        let (tag128, tag256) = decrypt(&key, &nonce, &mut ct, &ad);

        assert_ne!("c60b9c2d33ceb058f96e6dd03c215652", hex::encode(tag128));
        assert_ne!(
            "8c1cc703c81281bee3f6d9966e14948b4a175b2efbdc31e61a98b4465235c2d9",
            hex::encode(tag256)
        );
    }

    #[test]
    fn test_vector_9() {
        let key = hex!("1000020000000000000000000000000000000000000000000000000000000000");
        let nonce = hex!("1001000000000000000000000000000000000000000000000000000000000000");
        let ad = hex!("0001020304050607");
        let mut ct = hex!("f373079ed84b2709faee37358458");
        let (tag128, tag256) = decrypt(&key, &nonce, &mut ct, &ad);

        assert_ne!("c60b9c2d33ceb058f96e6dd03c215652", hex::encode(tag128));
        assert_ne!(
            "8c1cc703c81281bee3f6d9966e14948b4a175b2efbdc31e61a98b4465235c2d9",
            hex::encode(tag256)
        );
    }

    #[test]
    fn round_trip() {
        bolero::check!().with_type::<([u8; 32], [u8; 32], Vec<u8>, Vec<u8>)>().for_each(
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
        bolero::check!().with_type::<([u8; 32], [u8; 32], Vec<u8>, Vec<u8>)>().for_each(
            |(k, n, ad, msg)| {
                let mut ct = msg.clone();
                let (tag128, tag256) = encrypt(k, n, &mut ct, ad);

                let aegis16 = aegis::aegis256::Aegis256::<16>::new(k, n);
                let aegis32 = aegis::aegis256::Aegis256::<32>::new(k, n);

                assert_eq!(Ok(msg.to_vec()), aegis16.decrypt(&ct, &tag128, ad));
                assert_eq!(Ok(msg.to_vec()), aegis32.decrypt(&ct, &tag256, ad));
            },
        );
    }

    #[test]
    fn wycheproof() {
        let set = TestSet::load(TestName::Aegis256).expect("should have AEGIS-256 test vectors");
        for group in set.test_groups {
            for test in group.tests {
                let mut ct = test.pt.to_vec();
                let (tag128, _tag256) = encrypt(
                    &test.key.as_ref().try_into().expect("should be 32 bytes"),
                    &test.nonce.as_ref().try_into().expect("should be 32 bytes"),
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
