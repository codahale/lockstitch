#[cfg(target_arch = "aarch64")]
use self::aarch64::*;

#[cfg(target_arch = "x86_64")]
use self::x86_64::*;

#[cfg(target_arch = "aarch64")]
mod aarch64;

#[cfg(target_arch = "x86_64")]
mod x86_64;

pub fn encrypt(key: &[u8; 16], nonce: &[u8; 16], mc: &mut [u8], ad: &[u8]) -> [u8; 16] {
    let mut state = State::new(key, nonce);
    let mc_len = mc.len();
    let ad_len = ad.len();
    let mut src = [0u8; 32];
    let mut dst = [0u8; 32];
    let mut i = 0;
    while i + 32 <= ad_len {
        src.copy_from_slice(&ad[i..][..32]);
        state.absorb(&src);
        i += 32;
    }
    if ad_len % 32 != 0 {
        src.fill(0);
        src[..ad_len % 32].copy_from_slice(&ad[i..]);
        state.absorb(&src);
    }
    i = 0;
    while i + 32 <= mc_len {
        src.copy_from_slice(&mc[i..][..32]);
        state.enc(&mut dst, &src);
        mc[i..][..32].copy_from_slice(&dst);
        i += 32;
    }
    if mc_len % 32 != 0 {
        src.fill(0);
        src[..mc_len % 32].copy_from_slice(&mc[i..]);
        state.enc(&mut dst, &src);
        mc[i..].copy_from_slice(&dst[..mc_len % 32]);
    }

    state.mac(ad_len, mc_len)
}

pub fn decrypt(key: &[u8; 16], nonce: &[u8; 16], mc: &mut [u8], ad: &[u8]) -> [u8; 16] {
    let mut state = State::new(key, nonce);
    let mc_len = mc.len();
    let ad_len = ad.len();
    let mut src = [0u8; 32];
    let mut dst = [0u8; 32];
    let mut i = 0;
    while i + 32 <= ad_len {
        src.copy_from_slice(&ad[i..][..32]);
        state.enc(&mut dst, &src);
        i += 32;
    }
    if ad_len % 32 != 0 {
        src.fill(0);
        src[..ad_len % 32].copy_from_slice(&ad[i..]);
        state.enc(&mut dst, &src);
    }
    i = 0;
    while i + 32 <= mc_len {
        src.copy_from_slice(&mc[i..][..32]);
        state.dec(&mut dst, &src);
        mc[i..][..32].copy_from_slice(&dst);
        i += 32;
    }
    if mc_len % 32 != 0 {
        state.dec_partial(&mut dst, &mc[i..]);
        mc[i..].copy_from_slice(&dst[0..mc_len % 32]);
    }
    state.mac(ad_len, mc_len)
}

#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
struct State {
    blocks: [AesBlock; 8],
}

impl State {
    fn update(&mut self, d1: AesBlock, d2: AesBlock) {
        let blocks = &mut self.blocks;
        let tmp = blocks[7];
        let mut i = 7;
        while i > 0 {
            blocks[i] = round!(blocks[i - 1], blocks[i]);
            i -= 1;
        }
        blocks[0] = round!(tmp, blocks[0]);
        blocks[0] = xor!(blocks[0], d1);
        blocks[4] = xor!(blocks[4], d2);
    }

    pub fn new(key: &[u8; 16], nonce: &[u8; 16]) -> Self {
        let c1 = from_bytes!(&[
            0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5,
            0x28, 0xdd,
        ]);
        let c2 = from_bytes!(&[
            0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9,
            0x79, 0x62,
        ]);
        let key_block = from_bytes!(key);
        let nonce_block = from_bytes!(nonce);
        let blocks: [AesBlock; 8] = [
            xor!(key_block, nonce_block),
            c1,
            c2,
            c1,
            xor!(key_block, nonce_block),
            xor!(key_block, c2),
            xor!(key_block, c1),
            xor!(key_block, c2),
        ];
        let mut state = State { blocks };
        for _ in 0..10 {
            state.update(nonce_block, key_block);
        }
        state
    }

    #[inline(always)]
    fn absorb(&mut self, src: &[u8; 32]) {
        let msg0 = from_bytes!(&src[..16]);
        let msg1 = from_bytes!(&src[16..32]);
        self.update(msg0, msg1);
    }

    #[allow(unused_unsafe)]
    fn enc(&mut self, dst: &mut [u8; 32], src: &[u8; 32]) {
        let blocks = &self.blocks;
        let z0 = xor!(blocks[6], blocks[1], and!(blocks[2], blocks[3]));
        let z1 = xor!(blocks[2], blocks[5], and!(blocks[6], blocks[7]));
        let msg0 = from_bytes!(&src[..16]);
        let msg1 = from_bytes!(&src[16..32]);
        let c0 = xor!(msg0, z0);
        let c1 = xor!(msg1, z1);
        dst[..16].copy_from_slice(&as_bytes!(c0));
        dst[16..32].copy_from_slice(&as_bytes!(c1));
        self.update(msg0, msg1);
    }

    #[allow(unused_unsafe)]
    fn dec(&mut self, dst: &mut [u8; 32], src: &[u8; 32]) {
        let blocks = &self.blocks;
        let z0 = xor!(blocks[6], blocks[1], and!(blocks[2], blocks[3]));
        let z1 = xor!(blocks[2], blocks[5], and!(blocks[6], blocks[7]));
        let msg0 = xor!(from_bytes!(&src[0..16]), z0);
        let msg1 = xor!(from_bytes!(&src[16..32]), z1);
        dst[..16].copy_from_slice(&as_bytes!(msg0));
        dst[16..32].copy_from_slice(&as_bytes!(msg1));
        self.update(msg0, msg1);
    }

    #[allow(unused_unsafe)]
    fn dec_partial(&mut self, dst: &mut [u8; 32], src: &[u8]) {
        let len = src.len();
        let mut src_padded = [0u8; 32];
        src_padded[..len].copy_from_slice(src);

        let blocks = &self.blocks;
        let z0 = xor!(blocks[6], blocks[1], and!(blocks[2], blocks[3]));
        let z1 = xor!(blocks[2], blocks[5], and!(blocks[6], blocks[7]));
        let msg_padded0 = xor!(from_bytes!(&src_padded[0..16]), z0);
        let msg_padded1 = xor!(from_bytes!(&src_padded[16..32]), z1);

        dst[..16].copy_from_slice(&as_bytes!(msg_padded0));
        dst[16..32].copy_from_slice(&as_bytes!(msg_padded1));
        dst[len..].fill(0);

        let msg0 = from_bytes!(&dst[0..16]);
        let msg1 = from_bytes!(&dst[16..32]);
        self.update(msg0, msg1);
    }

    #[allow(unused_unsafe)]
    fn mac(&mut self, ad_len: usize, mc_len: usize) -> [u8; 16] {
        let tmp = {
            let blocks = &self.blocks;
            let mut sizes = [0u8; 16];
            sizes[..8].copy_from_slice(&(ad_len as u64 * 8).to_le_bytes());
            sizes[8..16].copy_from_slice(&(mc_len as u64 * 8).to_le_bytes());
            xor!(from_bytes!(&sizes), blocks[2])
        };
        for _ in 0..7 {
            let tmp2 = tmp;
            self.update(tmp, tmp2);
        }
        let blocks = &self.blocks;
        let mac = xor!(blocks[0], blocks[1], blocks[2], blocks[3], blocks[4], blocks[5], blocks[6]);
        as_bytes!(mac)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::array;
    use proptest::collection::vec;
    use proptest::prelude::*;

    #[test]
    fn round_trip() {
        let key = &[12; 16];
        let nonce = &[13; 16];
        let mut in_out = [69u8; 22];
        let tag_a = encrypt(key, nonce, &mut in_out, &[69]);
        let tag_b = decrypt(key, nonce, &mut in_out, &[69]);
        assert_eq!(in_out, [69u8; 22]);
        assert_eq!(tag_a, tag_b);
    }

    #[test]
    fn block_xor() {
        let a = from_bytes!(b"ayellowsubmarine");
        let b = from_bytes!(b"tuneintotheocho!");
        let c = xor!(a, b);

        assert_eq!(as_bytes!(c), [21, 12, 11, 9, 5, 1, 3, 28, 1, 10, 8, 14, 17, 1, 1, 68]);
    }

    #[test]
    fn block_and() {
        let a = from_bytes!(b"ayellowsubmarine");
        let b = from_bytes!(b"tuneintotheocho!");
        let c = and!(a, b);

        assert_eq!(
            as_bytes!(c),
            [96, 113, 100, 100, 104, 110, 116, 99, 116, 96, 101, 97, 98, 104, 110, 33]
        );
    }

    #[test]
    fn block_round() {
        let a = from_bytes!(b"ayellowsubmarine");
        let b = from_bytes!(b"tuneintotheocho!");
        let c = round!(a, b);

        assert_eq!(
            as_bytes!(c),
            [35, 216, 134, 65, 227, 155, 91, 10, 135, 68, 17, 98, 56, 180, 66, 103]
        );
    }

    #[test]
    fn test_aegis_in_place() {
        let m = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let ad = b"Comment numero un";
        let key = b"YELLOW SUBMARINE";
        let nonce = [0u8; 16];

        let mut mc = m.to_vec();
        let tag = encrypt(key, &nonce, &mut mc, ad);
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
        assert_eq!(tag, expected_tag);

        let tag = decrypt(key, &nonce, &mut mc, ad);
        assert_eq!(mc, m);
        assert_eq!(tag, expected_tag);
    }

    proptest! {
        #[test]
        fn decrypting_from_rust_aegis(
            k in array::uniform16(0u8..), n in array::uniform16(0u8..),
            ad in vec(any::<u8>(), 0..200), m in vec(any::<u8>(), 1..200),
        ) {
            let official = aegis::aegis128l::Aegis128L::new(&k, &n);
            let (c, tag_e) = official.encrypt(&m, &ad);
            let mut p = c.to_vec();
            let tag_d = decrypt(&k, &n, &mut p, &ad);

            prop_assert_eq!(m, p, "invalid decrypted plaintext");
            prop_assert_eq!(tag_e, tag_d, "invalid decrypted tag");
        }

        #[test]
        fn encrypting_to_rust_aegis(
            k in array::uniform16(0u8..), n in array::uniform16(0u8..),
            ad in vec(any::<u8>(), 0..200), m in vec(any::<u8>(), 1..200),
        ) {
            let mut c = m.clone();
            let tag = encrypt(&k, &n, &mut c, &ad);

            let official = aegis::aegis128l::Aegis128L::new(&k, &n);
            let p = official.decrypt(&c, &tag, &ad);

            prop_assert_eq!(Ok(m), p, "invalid decrypted plaintext");
        }
    }
}
