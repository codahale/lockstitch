#[cfg(target_arch = "x86")]
use core::arch::x86::{self as x86, *};

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::{self as x86, *};

/// An AES block.
pub use x86::__m128i as AesBlock;

/// Create an all-zero AES block.
#[inline]
pub fn zero() -> AesBlock {
    unsafe { _mm_setzero_si128() }
}

/// Load an AES block from the given slice.
#[inline]
pub fn load(bytes: &[u8]) -> AesBlock {
    unsafe { _mm_loadu_si128(bytes.as_ptr() as *const __m128i) }
}

/// Load an AES block from the two given u64 values as big-endian integers.
#[inline]
pub fn load_64x2(a: u64, b: u64) -> AesBlock {
    unsafe { _mm_set_epi64x(b as i64, a as i64) }
}

/// Store an AES block in the given slice.
#[inline]
pub fn store(bytes: &mut [u8], block: AesBlock) {
    unsafe { _mm_storeu_si128(bytes.as_mut_ptr() as *mut __m128i, block) };
}

/// Bitwise XOR the given AES blocks.
#[inline]
pub fn xor(a: AesBlock, b: AesBlock) -> AesBlock {
    unsafe { _mm_xor_si128(a, b) }
}

/// Bitwise XOR the given AES blocks.
#[inline]
pub fn xor3(a: AesBlock, b: AesBlock, c: AesBlock) -> AesBlock {
    unsafe { _mm_xor_si128(a, _mm_xor_si128(b, c)) }
}

/// Bitwise AND the given AES blocks.
#[inline]
pub fn and(a: AesBlock, b: AesBlock) -> AesBlock {
    unsafe { _mm_and_si128(a, b) }
}

/// Perform one AES round on the given state using the given round key.
#[inline]
pub fn enc(state: AesBlock, round_key: AesBlock) -> AesBlock {
    unsafe { _mm_aesenc_si128(state, round_key) }
}
