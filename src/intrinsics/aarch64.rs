use core::arch::aarch64::{self, *};
#[cfg(target_feature = "sha3")]
use core::arch::asm;

/// An AES block.
pub use aarch64::uint8x16_t as AesBlock;

/// Loads an AES block from the given slice.
#[inline]
pub fn load(bytes: &[u8]) -> AesBlock {
    unsafe { vld1q_u8(bytes.as_ptr()) }
}

/// Loads an AES block from the two given u64 values as big-endian integers.
#[inline]
pub fn load_64x2(a: u64, b: u64) -> AesBlock {
    unsafe { vreinterpretq_u8_u64(vsetq_lane_u64(b, vmovq_n_u64(a), 1)) }
}

/// Stores an AES block in the given slice.
#[inline]
pub fn store(bytes: &mut [u8], block: AesBlock) {
    unsafe { vst1q_u8(bytes.as_mut_ptr(), block) };
}

/// Bitwise XORs the given AES blocks.
#[inline]
pub fn xor(a: AesBlock, b: AesBlock) -> AesBlock {
    unsafe { veorq_u8(a, b) }
}

/// Bitwise XORs the given AES blocks.
#[inline]
#[cfg(target_feature = "sha3")]
pub fn xor3(a: AesBlock, b: AesBlock, c: AesBlock) -> AesBlock {
    // TODO replace with veor3q_u8 intrinsic when that's stable
    #[target_feature(enable = "sha3")]
    unsafe fn veor3q_u8(mut a: AesBlock, b: AesBlock, c: AesBlock) -> AesBlock {
        unsafe {
            asm!(
                "EOR3 {a:v}.16B, {a:v}.16B, {b:v}.16B, {c:v}.16B",
                a = inlateout(vreg) a, b = in(vreg) b, c = in(vreg) c,
                options(pure, nomem, nostack, preserves_flags)
            );
        };
        a
    }

    unsafe { veor3q_u8(a, b, c) }
}

/// Bitwise XORs the given AES blocks.
#[inline]
#[cfg(not(target_feature = "sha3"))]
pub fn xor3(a: AesBlock, b: AesBlock, c: AesBlock) -> AesBlock {
    xor(a, xor(b, c))
}

/// Bitwise ANDs the given AES blocks.
#[inline]
pub fn and(a: AesBlock, b: AesBlock) -> AesBlock {
    unsafe { vandq_u8(a, b) }
}

/// Performs one AES round on the given state using the given round key.
#[inline]
pub fn enc(state: AesBlock, round_key: AesBlock) -> AesBlock {
    unsafe { veorq_u8(vaesmcq_u8(vaeseq_u8(state, vmovq_n_u8(0))), round_key) }
}
