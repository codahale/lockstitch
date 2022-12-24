pub type AesBlock = core::arch::x86_64::__m128i;

macro_rules! from_bytes {
    ($bytes:expr) => {
        unsafe { core::arch::x86_64::_mm_loadu_si128($bytes.as_ptr() as *const _) }
    };
}

pub(crate) use from_bytes;

macro_rules! as_bytes {
    ($block:expr) => {{
        let mut bytes = [0u8; 16];
        unsafe { core::arch::x86_64::_mm_storeu_si128(bytes.as_mut_ptr() as *mut _, $block) };
        bytes
    }};
}

pub(crate) use as_bytes;

macro_rules! xor {
    ($a:expr) => {$a};
    ($a:expr, $($rest:expr),*) => {
        unsafe { core::arch::x86_64::_mm_xor_si128($a, xor!($($rest), *)) }
    };
}

pub(crate) use xor;

macro_rules! and {
    ($a:expr, $b:expr) => {
        unsafe { core::arch::x86_64::_mm_and_si128($a, $b) }
    };
}

pub(crate) use and;

macro_rules! round {
    ($a:expr, $b:expr) => {
        unsafe { core::arch::x86_64::_mm_aesenc_si128($a, $b) }
    };
}

pub(crate) use round;