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

#[derive(Debug, Clone)]
pub struct Aegis128L {
    blocks: [AesBlock; 8],
    ad_len: u64,
    mc_len: u64,
}

impl Aegis128L {
    pub fn new(key: &[u8; 16], nonce: &[u8; 16]) -> Self {
        // Initialize constants.
        let c0 = load!(&[
            0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9,
            0x79, 0x62,
        ]);
        let c1 = load!(&[
            0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5,
            0x28, 0xdd,
        ]);

        // Initialize key and nonce blocks.
        let key = load!(key);
        let nonce = load!(nonce);

        // Initialize cipher state.
        let mut state = Aegis128L {
            blocks: [
                xor!(key, nonce),
                c1,
                c0,
                c1,
                xor!(key, nonce),
                xor!(key, c0),
                xor!(key, c1),
                xor!(key, c0),
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
        let mut xi = [0u8; 32];

        let mut chunks = ad.chunks_exact(32);
        for chunk in chunks.by_ref() {
            xi.copy_from_slice(chunk);
            self.absorb(&xi);
        }

        let chunk = chunks.remainder();
        if !chunk.is_empty() {
            xi.fill(0);
            xi[..chunk.len()].copy_from_slice(chunk);
            self.absorb(&xi);
        }

        self.ad_len += ad.len() as u64;
    }

    pub fn prf(&mut self, out: &mut [u8]) {
        let mut ci = [0u8; 32];

        let mut chunks = out.chunks_exact_mut(32);
        for chunk in chunks.by_ref() {
            self.enc_zeroes(&mut ci);
            chunk.copy_from_slice(ci.as_slice());
        }

        let chunk = chunks.into_remainder();
        if !chunk.is_empty() {
            self.enc_zeroes(&mut ci);
            chunk.copy_from_slice(&ci[..chunk.len()]);
        }

        self.mc_len += out.len() as u64;
    }

    pub fn encrypt(&mut self, in_out: &mut [u8]) {
        let mut xi = [0u8; 32];
        let mut ci = [0u8; 32];

        let mut chunks = in_out.chunks_exact_mut(32);
        for chunk in chunks.by_ref() {
            xi.copy_from_slice(chunk);
            self.enc(&mut ci, &xi);
            chunk.copy_from_slice(ci.as_slice());
        }

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
        let mut ci = [0u8; 32];
        let mut xi = [0u8; 32];

        let mut chunks = in_out.chunks_exact_mut(32);
        for chunk in chunks.by_ref() {
            ci.copy_from_slice(chunk);
            self.dec(&mut xi, &ci);
            chunk.copy_from_slice(xi.as_slice());
        }

        let chunk = chunks.into_remainder();
        if !chunk.is_empty() {
            self.dec_partial(&mut xi, chunk);
            chunk.copy_from_slice(&xi[..chunk.len()]);
        }

        self.mc_len += in_out.len() as u64;
    }

    #[cfg(test)]
    fn absorb(&mut self, xi: &[u8; 32]) {
        let msg0 = load!(&xi[..16]);
        let msg1 = load!(&xi[16..]);
        self.update(msg0, msg1);
    }

    #[allow(unused_unsafe)]
    fn enc_zeroes(&mut self, ci: &mut [u8; 32]) {
        let blocks = &self.blocks;
        let z0 = xor!(blocks[6], blocks[1], and!(blocks[2], blocks[3]));
        let z1 = xor!(blocks[2], blocks[5], and!(blocks[6], blocks[7]));
        store!(&mut ci[..16], z0);
        store!(&mut ci[16..], z1);
        self.update(zero!(), zero!());
    }

    #[allow(unused_unsafe)]
    fn enc(&mut self, ci: &mut [u8; 32], xi: &[u8; 32]) {
        let blocks = &self.blocks;
        let z0 = xor!(blocks[6], blocks[1], and!(blocks[2], blocks[3]));
        let z1 = xor!(blocks[2], blocks[5], and!(blocks[6], blocks[7]));
        let t0 = load!(&xi[..16]);
        let t1 = load!(&xi[16..]);
        let out0 = xor!(t0, z0);
        let out1 = xor!(t1, z1);
        store!(&mut ci[..16], out0);
        store!(&mut ci[16..], out1);
        self.update(t0, t1);
    }

    #[allow(unused_unsafe)]
    fn dec(&mut self, xi: &mut [u8; 32], ci: &[u8; 32]) {
        let blocks = &self.blocks;
        let z0 = xor!(blocks[6], blocks[1], and!(blocks[2], blocks[3]));
        let z1 = xor!(blocks[2], blocks[5], and!(blocks[6], blocks[7]));
        let t0 = load!(&ci[..16]);
        let t1 = load!(&ci[16..]);
        let out0 = xor!(z0, t0);
        let out1 = xor!(z1, t1);
        store!(&mut xi[..16], out0);
        store!(&mut xi[16..], out1);
        self.update(out0, out1);
    }

    #[allow(unused_unsafe)]
    fn dec_partial(&mut self, xi: &mut [u8; 32], ci: &[u8]) {
        let mut src_padded = [0u8; 32];
        src_padded[..ci.len()].copy_from_slice(ci);

        let blocks = &self.blocks;
        let z0 = xor!(blocks[6], blocks[1], and!(blocks[2], blocks[3]));
        let z1 = xor!(blocks[2], blocks[5], and!(blocks[6], blocks[7]));
        let msg_padded0 = xor!(load!(&src_padded[..16]), z0);
        let msg_padded1 = xor!(load!(&src_padded[16..]), z1);

        store!(&mut xi[..16], msg_padded0);
        store!(&mut xi[16..], msg_padded1);
        xi[ci.len()..].fill(0);

        let msg0 = load!(&xi[..16]);
        let msg1 = load!(&xi[16..]);
        self.update(msg0, msg1);
    }

    #[allow(unused_unsafe)]
    pub fn finalize(&mut self) -> [u8; 16] {
        let mut sizes = [0u8; 16];
        sizes[..8].copy_from_slice(&(self.ad_len * 8).to_le_bytes());
        sizes[8..].copy_from_slice(&(self.mc_len * 8).to_le_bytes());
        let t = xor!(load!(&sizes), self.blocks[2]);

        for _ in 0..7 {
            self.update(t, t);
        }

        let mut tag = [0u8; 16];
        store!(
            &mut tag,
            xor!(
                xor!(self.blocks[0], self.blocks[1], self.blocks[2]),
                xor!(self.blocks[3], self.blocks[4], self.blocks[5]),
                self.blocks[6]
            )
        );
        tag
    }

    #[allow(unused_unsafe)]
    fn update(&mut self, m0: AesBlock, m1: AesBlock) {
        let blocks = &mut self.blocks;
        // Keep a temporary copy of block 7 so we can do in-place updates.
        let tmp = blocks[7];
        blocks[7] = enc!(blocks[6], blocks[7]);
        blocks[6] = enc!(blocks[5], blocks[6]);
        blocks[5] = enc!(blocks[4], blocks[5]);
        blocks[4] = xor!(enc!(blocks[3], blocks[4]), m1);
        blocks[3] = enc!(blocks[2], blocks[3]);
        blocks[2] = enc!(blocks[1], blocks[2]);
        blocks[1] = enc!(blocks[0], blocks[1]);
        blocks[0] = xor!(enc!(tmp, blocks[0]), m0);
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    use expect_test::expect;
    use hex_literal::hex;
    use proptest::collection::vec;
    use proptest::prelude::*;

    fn encrypt(key: &[u8; 16], nonce: &[u8; 16], mc: &mut [u8], ad: &[u8]) -> [u8; 16] {
        let mut state = Aegis128L::new(key, nonce);
        state.ad(ad);
        state.encrypt(mc);
        state.finalize()
    }

    fn decrypt(key: &[u8; 16], nonce: &[u8; 16], mc: &mut [u8], ad: &[u8]) -> [u8; 16] {
        let mut state = Aegis128L::new(key, nonce);
        state.ad(ad);
        state.decrypt(mc);
        state.finalize()
    }

    #[test]
    fn round_trip() {
        let key = &[12; 16];
        let nonce = &[13; 16];
        let mut in_out = [69u8; 17];
        let tag_a = encrypt(key, nonce, &mut in_out, &[69]);
        let tag_b = decrypt(key, nonce, &mut in_out, &[69]);
        assert_eq!(in_out, [69u8; 17]);
        assert_eq!(tag_a, tag_b);
    }

    #[test]
    fn block_xor() {
        let a = load!(b"ayellowsubmarine");
        let b = load!(b"tuneintotheocho!");
        let c = xor!(a, b);

        let mut c_bytes = [0u8; 16];
        store!(&mut c_bytes, c);

        expect!["150c0b090501031c010a080e11010144"].assert_eq(&hex::encode(c_bytes));
    }

    #[test]
    fn block_xor3() {
        let a = load!(b"ayellowsubmarine");
        let b = load!(b"tuneintotheocho!");
        let c = load!(b"mambonumbereight");
        let d = xor!(a, b, c);

        let mut d_bytes = [0u8; 16];
        store!(&mut d_bytes, d);

        expect!["786d666b6a6f7671636f7a6b78666930"].assert_eq(&hex::encode(d_bytes));
    }

    #[test]
    fn block_and() {
        let a = load!(b"ayellowsubmarine");
        let b = load!(b"tuneintotheocho!");
        let c = and!(a, b);

        let mut c_bytes = [0u8; 16];
        store!(&mut c_bytes, c);

        expect!["60716464686e74637460656162686e21"].assert_eq(&hex::encode(c_bytes));
    }

    // from https://www.ietf.org/archive/id/draft-irtf-cfrg-aegis-aead-01.html

    #[test]
    fn aes_round_test_vector() {
        let a = load!(&hex!("000102030405060708090a0b0c0d0e0f"));
        let b = load!(&hex!("101112131415161718191a1b1c1d1e1f"));
        let out = enc!(a, b);
        let mut c = [0u8; 16];
        store!(&mut c, out);

        expect!["7a7b4e5638782546a8c0477a3b813f43"].assert_eq(&hex::encode(c));
    }

    #[test]
    fn update_test_vector() {
        let mut state = Aegis128L {
            blocks: [
                load!(&hex!("9b7e60b24cc873ea894ecc07911049a3")),
                load!(&hex!("330be08f35300faa2ebf9a7b0d274658")),
                load!(&hex!("7bbd5bd2b049f7b9b515cf26fbe7756c")),
                load!(&hex!("c35a00f55ea86c3886ec5e928f87db18")),
                load!(&hex!("9ebccafce87cab446396c4334592c91f")),
                load!(&hex!("58d83e31f256371e60fc6bb257114601")),
                load!(&hex!("1639b56ea322c88568a176585bc915de")),
                load!(&hex!("640818ffb57dc0fbc2e72ae93457e39a")),
            ],
            ad_len: 0,
            mc_len: 0,
        };

        let d1 = load!(&hex!("033e6975b94816879e42917650955aa0"));
        let d2 = load!(&hex!("033e6975b94816879e42917650955aa0"));

        state.update(d1, d2);

        let mut blocks = [[0u8; 16]; 8];
        store!(&mut blocks[0], state.blocks[0]);
        store!(&mut blocks[1], state.blocks[1]);
        store!(&mut blocks[2], state.blocks[2]);
        store!(&mut blocks[3], state.blocks[3]);
        store!(&mut blocks[4], state.blocks[4]);
        store!(&mut blocks[5], state.blocks[5]);
        store!(&mut blocks[6], state.blocks[6]);
        store!(&mut blocks[7], state.blocks[7]);

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
        let (ct, tag) = {
            let mut msg = hex!("00000000000000000000000000000000");
            let tag = encrypt(&key, &nonce, &mut msg, &ad);
            (msg, tag)
        };

        expect!["c1c0e58bd913006feba00f4b3cc3594e"].assert_eq(&hex::encode(ct));
        expect!["abe0ece80c24868a226a35d16bdae37a"].assert_eq(&hex::encode(tag));
    }

    #[test]
    fn test_vector_2() {
        let key = hex!("10010000000000000000000000000000");
        let nonce = hex!("10000200000000000000000000000000");
        let ad = hex!("");
        let (ct, tag) = {
            let mut msg = [0u8; 0];
            let tag = encrypt(&key, &nonce, &mut msg, &ad);
            (msg, tag)
        };

        assert_eq!([0u8; 0], ct);
        expect!["c2b879a67def9d74e6c14f708bbcc9b4"].assert_eq(&hex::encode(tag));
    }

    #[test]
    fn test_vector_3() {
        let key = hex!("10010000000000000000000000000000");
        let nonce = hex!("10000200000000000000000000000000");
        let ad = hex!("0001020304050607");
        let (ct, tag) = {
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
        expect!["cc6f3372f6aa1bb82388d695c3962d9a"].assert_eq(&hex::encode(tag));
    }

    #[test]
    fn test_vector_4() {
        let key = hex!("10010000000000000000000000000000");
        let nonce = hex!("10000200000000000000000000000000");
        let ad = hex!("0001020304050607");
        let (ct, tag) = {
            let mut msg = hex!("000102030405060708090a0b0c0d");
            let tag = encrypt(&key, &nonce, &mut msg, &ad);
            (msg, tag)
        };

        expect!["79d94593d8c2119d7e8fd9b8fc77"].assert_eq(&hex::encode(ct));
        expect!["5c04b3dba849b2701effbe32c7f0fab7"].assert_eq(&hex::encode(tag));
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
        let (ct, tag) = {
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
        expect!["7542a745733014f9474417b337399507"].assert_eq(&hex::encode(tag));
    }

    #[test]
    fn test_vector_6() {
        let key = hex!("10000200000000000000000000000000");
        let nonce = hex!("10010000000000000000000000000000");
        let ad = hex!("0001020304050607");
        let mut ct = hex!("79d94593d8c2119d7e8fd9b8fc77");
        let tag = decrypt(&key, &nonce, &mut ct, &ad);

        assert_ne!(hex!("5c04b3dba849b2701effbe32c7f0fab7"), tag);
    }

    #[test]
    fn test_vector_7() {
        let key = hex!("10010000000000000000000000000000");
        let nonce = hex!("10000200000000000000000000000000");
        let ad = hex!("0001020304050607");
        let mut ct = hex!("79d94593d8c2119d7e8fd9b8fc78");
        let tag = decrypt(&key, &nonce, &mut ct, &ad);

        assert_ne!(hex!("5c04b3dba849b2701effbe32c7f0fab7"), tag);
    }

    #[test]
    fn test_vector_8() {
        let key = hex!("10010000000000000000000000000000");
        let nonce = hex!("10000200000000000000000000000000");
        let ad = hex!("0001020304050608");
        let mut ct = hex!("79d94593d8c2119d7e8fd9b8fc77");
        let tag = decrypt(&key, &nonce, &mut ct, &ad);

        assert_ne!(hex!("5c04b3dba849b2701effbe32c7f0fab7"), tag);
    }

    #[test]
    fn test_vector_9() {
        let key = hex!("10010000000000000000000000000000");
        let nonce = hex!("10000200000000000000000000000000");
        let ad = hex!("0001020304050607");
        let mut ct = hex!("79d94593d8c2119d7e8fd9b8fc77");
        let tag = decrypt(&key, &nonce, &mut ct, &ad);

        assert_ne!(hex!("6c04b3dba849b2701effbe32c7f0fab8"), tag);
    }

    proptest! {
        #[test]
        fn symmetric(
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
