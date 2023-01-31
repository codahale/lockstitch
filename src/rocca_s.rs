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
pub struct RoccaS {
    blocks: [AesBlock; 7],
    k0: AesBlock,
    k1: AesBlock,
    ad_len: u128,
    mc_len: u128,
}

impl RoccaS {
    pub fn new(key: &[u8; 32], nonce: &[u8; 16]) -> Self {
        const Z0: Aligned<A16, [u8; 16]> =
            Aligned([205, 101, 239, 35, 145, 68, 55, 113, 34, 174, 40, 215, 152, 47, 138, 66]);
        const Z1: Aligned<A16, [u8; 16]> =
            Aligned([188, 219, 137, 129, 165, 219, 181, 233, 47, 59, 77, 236, 207, 251, 192, 181]);
        let z0 = from_bytes!(&Z0, ..);
        let z1 = from_bytes!(&Z1, ..);
        let key = Aligned::<A16, _>(*key);
        let k0 = from_bytes!(&key, ..16);
        let k1 = from_bytes!(&key, 16..);
        let nonce = Aligned::<A16, _>(*nonce);
        let nonce = from_bytes!(&nonce, ..);
        let blocks: [AesBlock; 7] = [k1, nonce, z0, k0, z1, xor!(nonce, k1), zero!()];
        let mut state = RoccaS { blocks, k0, k1, ad_len: 0, mc_len: 0 };
        for _ in 0..16 {
            state.update(z0, z1);
        }

        state.blocks[0] = xor!(state.blocks[0], k0);
        state.blocks[1] = xor!(state.blocks[1], k0);
        state.blocks[2] = xor!(state.blocks[2], k1);
        state.blocks[3] = xor!(state.blocks[3], k0);
        state.blocks[4] = xor!(state.blocks[4], k0);
        state.blocks[5] = xor!(state.blocks[5], k1);
        state.blocks[6] = xor!(state.blocks[6], k1);

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

        self.ad_len += ad.len() as u128;
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

        self.mc_len += out.len() as u128;
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

        self.mc_len += in_out.len() as u128;
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

        self.mc_len += in_out.len() as u128;
    }

    #[cfg(test)]
    fn absorb(&mut self, src: &Aligned<A16, [u8; 32]>) {
        let msg0 = from_bytes!(src, ..16);
        let msg1 = from_bytes!(src, 16..);
        self.update(msg0, msg1);
    }

    #[allow(unused_unsafe)]
    fn enc_zeroes(&mut self, dst: &mut Aligned<A16, [u8; 32]>) {
        let blocks = &self.blocks;
        let c0 = round!(xor!(blocks[3], blocks[5]), blocks[0]);
        let c1 = round!(xor!(blocks[4], blocks[6]), blocks[2]);
        to_bytes!(dst, ..16, c0);
        to_bytes!(dst, 16.., c1);
        self.update(zero!(), zero!());
    }

    #[allow(unused_unsafe)]
    fn enc(&mut self, dst: &mut Aligned<A16, [u8; 32]>, src: &Aligned<A16, [u8; 32]>) {
        let blocks = &self.blocks;
        let msg0 = from_bytes!(src, ..16);
        let msg1 = from_bytes!(src, 16..);
        let k0 = round!(xor!(blocks[3], blocks[5]), blocks[0]);
        let k1 = round!(xor!(blocks[4], blocks[6]), blocks[2]);
        let c0 = xor!(k0, msg0);
        let c1 = xor!(k1, msg1);
        to_bytes!(dst, ..16, c0);
        to_bytes!(dst, 16.., c1);
        self.update(msg0, msg1);
    }

    #[allow(unused_unsafe)]
    fn dec(&mut self, dst: &mut Aligned<A16, [u8; 32]>, src: &Aligned<A16, [u8; 32]>) {
        let blocks = &self.blocks;
        let c0 = from_bytes!(src, ..16);
        let c1 = from_bytes!(src, 16..);
        let k0 = round!(xor!(blocks[3], blocks[5]), blocks[0]);
        let k1 = round!(xor!(blocks[4], blocks[6]), blocks[2]);
        let msg0 = xor!(k0, c0);
        let msg1 = xor!(k1, c1);
        to_bytes!(dst, ..16, xor!(k0, c0));
        to_bytes!(dst, 16.., xor!(k1, c1));
        self.update(msg0, msg1);
    }

    #[allow(unused_unsafe)]
    fn dec_partial(&mut self, dst: &mut Aligned<A16, [u8; 32]>, src: &[u8]) {
        let mut src_padded = Aligned::<A16, _>([0u8; 32]);
        src_padded[..src.len()].copy_from_slice(src);

        let blocks = &self.blocks;
        let c0 = from_bytes!(&src_padded, ..16);
        let c1 = from_bytes!(&src_padded, 16..);
        let k0 = round!(xor!(blocks[3], blocks[5]), blocks[0]);
        let k1 = round!(xor!(blocks[4], blocks[6]), blocks[2]);
        let msg_padded0 = xor!(k0, c0);
        let msg_padded1 = xor!(k1, c1);
        to_bytes!(dst, ..16, msg_padded0);
        to_bytes!(dst, 16.., msg_padded1);
        dst[src.len()..].fill(0);

        let msg0 = from_bytes!(dst, ..16);
        let msg1 = from_bytes!(dst, 16..);
        self.update(msg0, msg1);
    }

    #[allow(unused_unsafe)]
    pub fn tag(&mut self) -> [u8; 32] {
        self.blocks[1] = xor!(self.blocks[1], self.k0);
        self.blocks[2] = xor!(self.blocks[2], self.k1);

        let ad_block = from_bytes!(&Aligned::<A16, _>((self.ad_len * 8).to_le_bytes()), ..);
        let mc_block = from_bytes!(&Aligned::<A16, _>((self.mc_len * 8).to_le_bytes()), ..);

        for _ in 0..16 {
            self.update(ad_block, mc_block);
        }

        let blocks = &self.blocks;
        let mut tag = Aligned::<A16, _>([0u8; 32]);
        to_bytes!(&mut tag, ..16, xor!(blocks[0], blocks[1], blocks[2], blocks[3]));
        to_bytes!(&mut tag, 16.., xor!(blocks[4], blocks[5], blocks[6]));
        *tag
    }

    #[allow(unused_unsafe)]
    fn update(&mut self, x0: AesBlock, x1: AesBlock) {
        let new_blocks = [
            xor!(self.blocks[6], self.blocks[1]),
            round!(self.blocks[0], x0),
            round!(self.blocks[1], self.blocks[0]),
            round!(self.blocks[2], self.blocks[6]),
            round!(self.blocks[3], x1),
            round!(self.blocks[4], self.blocks[3]),
            round!(self.blocks[5], self.blocks[4]),
        ];
        self.blocks = new_blocks;
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    use hex_literal::hex;

    fn encrypt(key: &[u8; 32], nonce: &[u8; 16], mc: &mut [u8], ad: &[u8]) -> [u8; 32] {
        let mut state = RoccaS::new(key, nonce);
        state.ad(ad);
        state.encrypt(mc);
        state.tag()
    }

    fn decrypt(key: &[u8; 32], nonce: &[u8; 16], mc: &mut [u8], ad: &[u8]) -> [u8; 32] {
        let mut state = RoccaS::new(key, nonce);
        state.ad(ad);
        state.decrypt(mc);
        state.tag()
    }

    #[test]
    fn round_trip() {
        let key = &[12; 32];
        let nonce = &[13; 16];
        let mut in_out = [69u8; 17];
        let tag_a = encrypt(key, nonce, &mut in_out, &[69]);
        let tag_b = decrypt(key, nonce, &mut in_out, &[69]);
        assert_eq!(in_out, [69u8; 17]);
        assert_eq!(tag_a, tag_b);
    }

    // from https://www.ietf.org/archive/id/draft-nakano-rocca-s-02.html#name-test-vector

    #[test]
    fn test_vector_1() {
        let key = &[0; 32];
        let nonce = &[0; 16];
        let ad = &[0; 32];
        let mut in_out = [0; 64];
        let tag_a = encrypt(key, nonce, &mut in_out, ad);

        assert_eq!(
            hex!(
                "9a c3 32 64 95 a8 d4 14 fe 40 7f 47 b5 44 10 50"
                "24 81 cf 79 ca b8 c0 a6 69 32 3e 07 71 1e 46 17"
                "0d e5 b2 fb ba 0f ae 8d e7 c1 fc ca ee fc 36 26"
                "24 fc fd c1 5f 8b b3 e6 44 57 e8 b7 e3 75 57 bb"
            ),
            in_out
        );
        assert_eq!(
            hex!(
                "8d f9 34 d1 48 37 10 c9 41 0f 6a 08 9c 4c ed 97"
                "91 90 1b 7e 2e 66 12 06 20 2d b2 cc 7a 24 a3 86"
            ),
            tag_a
        );
    }

    #[test]
    fn test_vector_2() {
        let key = &[1; 32];
        let nonce = &[1; 16];
        let ad = &[1; 32];
        let mut in_out = [0; 64];
        let tag_a = encrypt(key, nonce, &mut in_out, ad);

        assert_eq!(
            hex!(
                "55 9e cb 25 3b cf e2 6b 48 3b f0 0e 9c 74 83 45"
                "97 8f f9 21 03 6a 6c 1f dc b7 12 17 28 36 50 4f"
                "bc 64 d4 30 a7 3f c6 7a cd 3c 3b 9c 19 76 d8 07"
                "90 f4 83 57 e7 fe 0c 06 82 62 45 69 d3 a6 58 fb"
            ),
            in_out
        );
        assert_eq!(
            hex!(
                "b7 30 e6 b6 19 f6 3c cf 7e 69 73 59 14 d7 6a b5"
                "2f 70 36 0c 8a 65 4b ad 99 13 20 ef 95 2c 40 a2"
            ),
            tag_a
        );
    }

    #[test]
    fn test_vector_3() {
        let key = &hex!(
            "01 23 45 67 89 ab cd ef 01 23 45 67 89 ab cd ef"
            "01 23 45 67 89 ab cd ef 01 23 45 67 89 ab cd ef"
        );
        let nonce = &hex!("01 23 45 67 89 ab cd ef 01 23 45 67 89 ab cd ef");
        let ad = &hex!(
            "01 23 45 67 89 ab cd ef 01 23 45 67 89 ab cd ef"
            "01 23 45 67 89 ab cd ef 01 23 45 67 89 ab cd ef"
        );
        let mut in_out = [0; 64];
        let tag_a = encrypt(key, nonce, &mut in_out, ad);

        assert_eq!(
            hex!(
                "b5 fc 4e 2a 72 b8 6d 1a 13 3c 0f 02 02 bd f7 90"
                "af 14 a2 4b 2c db 67 6e 42 78 65 e1 2f cc 9d 30"
                "21 d1 84 18 fc 75 dc 19 12 dd 2c d7 9a 3b ee b2"
                "a9 8b 23 5d e2 29 9b 9d da 93 fd 2b 5a c8 f4 36"
            ),
            in_out
        );
        assert_eq!(
            hex!(
                "32 6e 63 57 e5 00 34 a7 75 0f c2 01 31 aa 6f 76"
                "19 ed 23 db 5b da d0 00 28 20 cc 70 7f 35 9f 8d"
            ),
            tag_a
        );
    }
}
