pub use core::arch::x86_64::__m128i as AesBlock;
pub use core::arch::x86_64::*;

macro_rules! from_bytes {
    ($bytes:expr) => {{
        let block: &[u8] = $bytes; // N.B.: loads are broken without this aliasing
        _mm_loadu_si128(block.as_ptr() as *const __m128i)
    }};
}

pub(crate) use from_bytes;

macro_rules! as_bytes {
    ($block:expr) => {{
        let mut bytes = Aligned::<A16, _>([0u8; 16]);
        _mm_storeu_si128(bytes.as_mut_ptr() as *mut __m128i, $block);
        bytes
    }};
}

pub(crate) use as_bytes;

macro_rules! xor {
    ($a:expr) => {$a};
    ($a:expr, $($rest:expr),*) => {
        _mm_xor_si128($a, xor!($($rest), *))
    };
}

pub(crate) use xor;

macro_rules! and {
    ($a:expr, $b:expr) => {
        _mm_and_si128($a, $b)
    };
}

pub(crate) use and;

macro_rules! round {
    ($a:expr, $b:expr) => {
        _mm_aesenc_si128($a, $b)
    };
}

pub(crate) use round;
