#[cfg(target_arch = "x86")]
pub use core::arch::x86::*;

#[cfg(target_arch = "x86_64")]
pub use core::arch::x86_64::*;

pub use self::__m128i as AesBlock;

macro_rules! zero {
    () => {
        unsafe { _mm_setzero_si128() }
    };
}

pub(crate) use zero;

macro_rules! load {
    ($bytes:expr, $idx:expr) => {{
        let bytes: &Aligned<A16, _> = $bytes;
        unsafe { _mm_load_si128(bytes[$idx].as_ptr() as *const __m128i) }
    }};
}

pub(crate) use load;

macro_rules! store {
    ($bytes:expr, $idx:expr, $block:expr) => {{
        let bytes: &mut Aligned<A16, _> = $bytes;
        unsafe { _mm_store_si128(bytes[$idx].as_mut_ptr() as *mut __m128i, $block) };
    }};
}

pub(crate) use store;

macro_rules! xor {
    ($a:expr) => {$a};
    ($a:expr, $($rest:expr),*) => {
        unsafe { _mm_xor_si128($a, xor!($($rest), *)) }
    };
}

pub(crate) use xor;

macro_rules! enc {
    ($a:expr, $b:expr) => {
        unsafe { _mm_aesenc_si128($a, $b) }
    };
}

pub(crate) use enc;
