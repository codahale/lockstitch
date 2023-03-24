use aligned::{Aligned, A16};

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
        let c1 = load!(
            &Aligned::<A16, _>([
                0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5,
                0x28, 0xdd,
            ]),
            ..
        );
        let c2 = load!(
            &Aligned::<A16, _>([
                0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9,
                0x79, 0x62,
            ]),
            ..
        );
        let key = load!(&Aligned::<A16, _>(*key), ..);
        let nonce = load!(&Aligned::<A16, _>(*nonce), ..);
        let blocks: [AesBlock; 8] = [
            xor!(key, nonce),
            c1,
            c2,
            c1,
            xor!(key, nonce),
            xor!(key, c2),
            xor!(key, c1),
            xor!(key, c2),
        ];
        let mut state = Aegis128L { blocks, ad_len: 0, mc_len: 0 };
        for _ in 0..10 {
            state.update(nonce, key);
        }
        state
    }

    #[cfg(test)]
    pub fn ad(&mut self, ad: &[u8]) {
        let mut src = Aligned::<A16, _>([0u8; 32]);

        let mut chunks = ad.chunks_exact(32);
        for chunk in chunks.by_ref() {
            src.copy_from_slice(chunk);
            self.absorb(&src);
        }

        let chunk = chunks.remainder();
        if !chunk.is_empty() {
            src.fill(0);
            src[..chunk.len()].copy_from_slice(chunk);
            self.absorb(&src);
        }

        self.ad_len += ad.len() as u64;
    }

    pub fn prf(&mut self, out: &mut [u8]) {
        let mut dst = Aligned::<A16, _>([0u8; 32]);

        let mut chunks = out.chunks_exact_mut(32);
        for chunk in chunks.by_ref() {
            self.enc_zeroes(&mut dst);
            chunk.copy_from_slice(dst.as_slice());
        }

        let chunk = chunks.into_remainder();
        if !chunk.is_empty() {
            self.enc_zeroes(&mut dst);
            chunk.copy_from_slice(&dst[..chunk.len()]);
        }

        self.mc_len += out.len() as u64;
    }

    pub fn encrypt(&mut self, in_out: &mut [u8]) {
        let mut src = Aligned::<A16, _>([0u8; 32]);
        let mut dst = Aligned::<A16, _>([0u8; 32]);

        let mut chunks = in_out.chunks_exact_mut(32);
        for chunk in chunks.by_ref() {
            src.copy_from_slice(chunk);
            self.enc(&mut dst, &src);
            chunk.copy_from_slice(dst.as_slice());
        }

        let chunk = chunks.into_remainder();
        if !chunk.is_empty() {
            src.fill(0);
            src[..chunk.len()].copy_from_slice(chunk);
            self.enc(&mut dst, &src);
            chunk.copy_from_slice(&dst[..chunk.len()]);
        }

        self.mc_len += in_out.len() as u64;
    }

    pub fn decrypt(&mut self, in_out: &mut [u8]) {
        let mut src = Aligned::<A16, _>([0u8; 32]);
        let mut dst = Aligned::<A16, _>([0u8; 32]);

        let mut chunks = in_out.chunks_exact_mut(32);
        for chunk in chunks.by_ref() {
            src.copy_from_slice(chunk);
            self.dec(&mut dst, &src);
            chunk.copy_from_slice(dst.as_slice());
        }

        let chunk = chunks.into_remainder();
        if !chunk.is_empty() {
            self.dec_partial(&mut dst, chunk);
            chunk.copy_from_slice(&dst[..chunk.len()]);
        }

        self.mc_len += in_out.len() as u64;
    }

    #[cfg(test)]
    fn absorb(&mut self, src: &Aligned<A16, [u8; 32]>) {
        let msg0 = load!(src, ..16);
        let msg1 = load!(src, 16..);
        self.update(msg0, msg1);
    }

    #[allow(unused_unsafe)]
    fn enc_zeroes(&mut self, dst: &mut Aligned<A16, [u8; 32]>) {
        let blocks = &self.blocks;
        let z0 = xor!(blocks[6], blocks[1], and!(blocks[2], blocks[3]));
        let z1 = xor!(blocks[2], blocks[5], and!(blocks[6], blocks[7]));
        store!(dst, ..16, z0);
        store!(dst, 16.., z1);
        self.update(zero!(), zero!());
    }

    #[allow(unused_unsafe)]
    fn enc(&mut self, dst: &mut Aligned<A16, [u8; 32]>, src: &Aligned<A16, [u8; 32]>) {
        let blocks = &self.blocks;
        let z0 = xor!(blocks[6], blocks[1], and!(blocks[2], blocks[3]));
        let z1 = xor!(blocks[2], blocks[5], and!(blocks[6], blocks[7]));
        let msg0 = load!(src, ..16);
        let msg1 = load!(src, 16..);
        let c0 = xor!(msg0, z0);
        let c1 = xor!(msg1, z1);
        store!(dst, ..16, c0);
        store!(dst, 16.., c1);
        self.update(msg0, msg1);
    }

    #[allow(unused_unsafe)]
    fn dec(&mut self, dst: &mut Aligned<A16, [u8; 32]>, src: &Aligned<A16, [u8; 32]>) {
        let blocks = &self.blocks;
        let z0 = xor!(blocks[6], blocks[1], and!(blocks[2], blocks[3]));
        let z1 = xor!(blocks[2], blocks[5], and!(blocks[6], blocks[7]));
        let c0 = load!(src, ..16);
        let c1 = load!(src, 16..);
        let msg0 = xor!(z0, c0);
        let msg1 = xor!(z1, c1);
        store!(dst, ..16, msg0);
        store!(dst, 16.., msg1);
        self.update(msg0, msg1);
    }

    #[allow(unused_unsafe)]
    fn dec_partial(&mut self, dst: &mut Aligned<A16, [u8; 32]>, src: &[u8]) {
        let mut src_padded = Aligned::<A16, _>([0u8; 32]);
        src_padded[..src.len()].copy_from_slice(src);

        let blocks = &self.blocks;
        let z0 = xor!(blocks[6], blocks[1], and!(blocks[2], blocks[3]));
        let z1 = xor!(blocks[2], blocks[5], and!(blocks[6], blocks[7]));
        let msg_padded0 = xor!(load!(&src_padded, ..16), z0);
        let msg_padded1 = xor!(load!(&src_padded, 16..), z1);

        store!(dst, ..16, msg_padded0);
        store!(dst, 16.., msg_padded1);
        dst[src.len()..].fill(0);

        let msg0 = load!(dst, ..16);
        let msg1 = load!(dst, 16..);
        self.update(msg0, msg1);
    }

    #[allow(unused_unsafe)]
    pub fn tag(&mut self) -> [u8; 16] {
        let mut sizes = Aligned::<A16, _>([0u8; 16]);
        sizes[..8].copy_from_slice(&(self.ad_len * 8).to_le_bytes());
        sizes[8..].copy_from_slice(&(self.mc_len * 8).to_le_bytes());
        let tmp = xor!(load!(&sizes, ..), self.blocks[2]);

        for _ in 0..7 {
            self.update(tmp, tmp);
        }

        let mut tag = Aligned::<A16, _>([0u8; 16]);
        store!(
            &mut tag,
            ..,
            xor!(
                self.blocks[0],
                self.blocks[1],
                self.blocks[2],
                self.blocks[3],
                self.blocks[4],
                self.blocks[5],
                self.blocks[6]
            )
        );
        *tag
    }

    #[allow(unused_unsafe)]
    fn update(&mut self, d1: AesBlock, d2: AesBlock) {
        let blocks = &mut self.blocks;
        let tmp = blocks[7];
        blocks[7] = enc!(blocks[6], blocks[7]);
        blocks[6] = enc!(blocks[5], blocks[6]);
        blocks[5] = enc!(blocks[4], blocks[5]);
        blocks[4] = xor!(enc!(blocks[3], blocks[4]), d2);
        blocks[3] = enc!(blocks[2], blocks[3]);
        blocks[2] = enc!(blocks[1], blocks[2]);
        blocks[1] = enc!(blocks[0], blocks[1]);
        blocks[0] = xor!(enc!(tmp, blocks[0]), d1);
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    use hex_literal::hex;
    use proptest::collection::vec;
    use proptest::prelude::*;

    fn encrypt(key: &[u8; 16], nonce: &[u8; 16], mc: &mut [u8], ad: &[u8]) -> [u8; 16] {
        let mut state = Aegis128L::new(key, nonce);
        state.ad(ad);
        state.encrypt(mc);
        state.tag()
    }

    fn decrypt(key: &[u8; 16], nonce: &[u8; 16], mc: &mut [u8], ad: &[u8]) -> [u8; 16] {
        let mut state = Aegis128L::new(key, nonce);
        state.ad(ad);
        state.decrypt(mc);
        state.tag()
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

    // from https://www.ietf.org/archive/id/draft-irtf-cfrg-aegis-aead-01.html

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

        assert_eq!(hex!("c1c0e58bd913006feba00f4b3cc3594e"), ct);
        assert_eq!(hex!("abe0ece80c24868a226a35d16bdae37a"), tag);
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
        assert_eq!(hex!("c2b879a67def9d74e6c14f708bbcc9b4"), tag);
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
        assert_eq!(hex!("cc6f3372f6aa1bb82388d695c3962d9a"), tag);
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

        assert_eq!(hex!("79d94593d8c2119d7e8fd9b8fc77"), ct);
        assert_eq!(hex!("5c04b3dba849b2701effbe32c7f0fab7"), tag);
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
        assert_eq!(hex!("7542a745733014f9474417b337399507"), tag);
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
