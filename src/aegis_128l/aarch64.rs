pub use core::arch::aarch64::*;
pub use core::arch::asm;

/// An AES block.
pub use self::uint8x16_t as AesBlock;

/// Create an all-zero AES block.
#[inline(always)]
pub fn zero() -> AesBlock {
    unsafe { vmovq_n_u8(0) }
}

/// Load an AES block from the given slice.
#[inline(always)]
pub fn load(bytes: &[u8]) -> AesBlock {
    unsafe { vld1q_u8(bytes.as_ptr()) }
}

/// Load an AES block from the two given u64 values as big-endian integers.
#[inline(always)]
pub fn load_64x2(a: u64, b: u64) -> AesBlock {
    unsafe { vreinterpretq_u8_u64(vsetq_lane_u64(b, vmovq_n_u64(a), 1)) }
}

/// Store an AES block in the given slice.
#[inline(always)]
pub fn store(bytes: &mut [u8], block: AesBlock) {
    unsafe { vst1q_u8(bytes.as_mut_ptr(), block) };
}

/// Bitwise XOR the given AES blocks.
#[inline(always)]
pub fn xor(a: AesBlock, b: AesBlock) -> AesBlock {
    unsafe { veorq_u8(a, b) }
}

/// Bitwise XOR the given AES blocks.
#[inline(always)]
pub fn xor3(a: AesBlock, b: AesBlock, c: AesBlock) -> AesBlock {
    // TODO replace with veor3q_u8 intrinsic when that's stable
    #[target_feature(enable = "sha3")]
    unsafe fn veor3q_u8(a: AesBlock, b: AesBlock, c: AesBlock) -> AesBlock {
        let mut ret: AesBlock;
        asm!(
            "EOR3 {:v}.16B, {:v}.16B, {:v}.16B, {:v}.16B",
            out(vreg) ret, in(vreg) a, in(vreg) b, in(vreg) c,
            options(pure, nomem, nostack, preserves_flags)
        );
        ret
    }
    unsafe { veor3q_u8(a, b, c) }
}

/// Bitwise AND the given AES blocks.
#[inline(always)]
pub fn and(a: AesBlock, b: AesBlock) -> AesBlock {
    unsafe { vandq_u8(a, b) }
}

/// Perform one AES round on the given state using the given round key.
#[inline(always)]
pub fn enc(state: AesBlock, round_key: AesBlock) -> AesBlock {
    // TODO replace with vaeseq_u8 and vaesmcq_u8 instrinsics when that's stable
    #[target_feature(enable = "aes")]
    unsafe fn vaeseq_u8_and_vaesmcq_u8(mut state: AesBlock) -> AesBlock {
        let z = vmovq_n_u8(0);
        asm!(
            "AESE {0:v}.16B, {1:v}.16B",
            "AESMC {0:v}.16B, {0:v}.16B",
            inout(vreg) state, in(vreg) z,
            options(pure, nomem, nostack, preserves_flags)
        );
        state
    }
    unsafe { veorq_u8(vaeseq_u8_and_vaesmcq_u8(state), round_key) }
}
