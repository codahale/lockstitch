#[cfg(target_arch = "x86")]
pub use core::arch::x86::*;

#[cfg(target_arch = "x86_64")]
pub use core::arch::x86_64::*;

/// An AES block.
pub use self::__m128i as AesBlock;

/// Create an all-zero AES block.
macro_rules! zero {
    () => {{
        unsafe { _mm_setzero_si128() }
    }};
}

pub(crate) use zero;

/// Load an AES block from the given slice.
macro_rules! load {
    ($bytes:expr) => {{
        let block: &[u8] = $bytes; // N.B.: loads are broken without this aliasing
        unsafe { _mm_loadu_si128(block.as_ptr() as *const __m128i) }
    }};
}

pub(crate) use load;

/// Load an AES block from the two given u64 values as big-endian integers.
macro_rules! load_64x2 {
    ($a:expr, $b:expr) => {{
        unsafe { _mm_set_epi64x($b.try_into().unwrap(), $a.try_into().unwrap()) }
    }};
}

pub(crate) use load_64x2;

/// Store an AES block in the given slice.
macro_rules! store {
    ($bytes:expr, $block:expr) => {{
        unsafe { _mm_storeu_si128($bytes.as_mut_ptr() as *mut __m128i, $block) };
    }};
}

pub(crate) use store;

/// Bitwise XOR the given AES blocks.
macro_rules! xor {
    ($a:expr, $b:expr) => {{
        unsafe { _mm_xor_si128($a, $b) }
    }};
    ($a:expr, $b:expr, $c:expr) => {{
        let b = xor!($b, $c);
        unsafe { _mm_xor_si128($a, b) }
    }};
}

pub(crate) use xor;

/// Bitwise AND the given AES blocks.
macro_rules! and {
    ($a:expr, $b:expr) => {{
        unsafe { _mm_and_si128($a, $b) }
    }};
}

pub(crate) use and;

/// Perform one AES round on the given state using the given round key.
macro_rules! enc {
    ($state:expr, $round_key:expr) => {{
        unsafe { _mm_aesenc_si128($state, $round_key) }
    }};
}

pub(crate) use enc;
