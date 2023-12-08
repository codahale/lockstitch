#[cfg(all(target_arch = "aarch64", not(feature = "portable")))]
pub use self::aarch64::*;

#[cfg(feature = "portable")]
pub use self::portable::*;

#[cfg(all(any(target_arch = "x86_64", target_arch = "x86"), not(feature = "portable")))]
pub use self::x86_64::*;

#[cfg(all(target_arch = "aarch64", not(feature = "portable")))]
mod aarch64;

#[cfg(feature = "portable")]
mod portable;

#[cfg(all(any(target_arch = "x86_64", target_arch = "x86"), not(feature = "portable")))]
mod x86_64;

/// The length of an AES block.
pub const AES_BLOCK_LEN: usize = 16;

/// Loads two AES blocks from the given slice.
#[inline]
pub fn load_2x(bytes: &[u8]) -> (AesBlock, AesBlock) {
    let (hi, lo) = bytes.split_at(AES_BLOCK_LEN);
    (load(hi), load(lo))
}

/// Stores two AES blocks in the given slice.
#[inline]
pub fn store_2x(bytes: &mut [u8], hi: AesBlock, lo: AesBlock) {
    let (b_hi, b_lo) = bytes.split_at_mut(AES_BLOCK_LEN);
    store(b_hi, hi);
    store(b_lo, lo);
}
