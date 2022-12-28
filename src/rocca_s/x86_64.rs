pub use core::arch::x86_64::__m128i as AesBlock;
pub use core::arch::x86_64::*;

macro_rules! zero {
    () => {{
        let block = Aligned::<A16, _>([0u8; 16]);
        unsafe { _mm_loadu_si128(block.as_ptr() as *const __m128i) }
    }};
}

pub(crate) use zero;

macro_rules! from_bytes {
    ($bytes:expr, $idx:expr) => {{
        let bytes: &Aligned<A16, _> = $bytes;
        unsafe { _mm_loadu_si128(bytes[$idx].as_ptr() as *const __m128i) }
    }};
}

pub(crate) use from_bytes;

macro_rules! to_bytes {
    ($bytes:expr, $idx:expr, $block:expr) => {{
        let bytes: &mut Aligned<A16, _> = $bytes;
        unsafe { _mm_storeu_si128(bytes[$idx].as_mut_ptr() as *mut __m128i, $block) };
    }};
}

pub(crate) use to_bytes;

macro_rules! xor {
    ($a:expr) => {$a};
    ($a:expr, $($rest:expr),*) => {
        unsafe { _mm_xor_si128($a, xor!($($rest), *)) }
    };
}

pub(crate) use xor;

macro_rules! round {
    ($a:expr, $b:expr) => {
        unsafe { _mm_aesenc_si128($a, $b) }
    };
}

pub(crate) use round;
