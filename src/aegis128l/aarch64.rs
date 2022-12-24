pub type AesBlock = core::arch::aarch64::uint8x16_t;

macro_rules! from_bytes {
    ($bytes:expr) => {
        unsafe { core::arch::aarch64::vld1q_u8($bytes.as_ptr()) }
    };
}

pub(crate) use from_bytes;

macro_rules! as_bytes {
    ($block:expr) => {{
        let mut bytes = [0u8; 16];
        unsafe { core::arch::aarch64::vst1q_u8(bytes.as_mut_ptr(), $block) };
        bytes
    }};
}

pub(crate) use as_bytes;

macro_rules! xor {
    ($a:expr) => {$a};
    ($a:expr, $($rest:expr),*) => {
        unsafe { core::arch::aarch64::veorq_u8($a, xor!($($rest), *)) }
    };
}

pub(crate) use xor;

macro_rules! and {
    ($a:expr, $b:expr) => {
        unsafe { core::arch::aarch64::vandq_u8($a, $b) }
    };
}

pub(crate) use and;

macro_rules! round {
    ($a:expr, $b:expr) => {
       unsafe {
            let z = core::arch::aarch64::vmovq_n_u8(0);
            let mut a = $a;
            core::arch::asm!(
                "AESE {0:v}.16B, {1:v}.16B",
                "AESMC {0:v}.16B, {0:v}.16B",
                inout(vreg) a, in(vreg) z);
            core::arch::aarch64::veorq_u8(a, $b)
       }
    };
}

pub(crate) use round;
