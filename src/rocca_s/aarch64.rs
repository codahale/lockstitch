pub use core::arch::aarch64::uint8x16_t as AesBlock;
pub use core::arch::aarch64::*;
pub use core::arch::asm;

macro_rules! zero {
    () => {{
        unsafe { vmovq_n_u8(0) }
    }};
}

pub(crate) use zero;

macro_rules! load {
    ($bytes:expr,$idx:expr) => {{
        let bytes: &Aligned<A16, _> = $bytes;
        unsafe { vld1q_u8(bytes[$idx].as_ptr()) }
    }};
}

pub(crate) use load;

macro_rules! store {
    ($bytes:expr, $idx:expr, $block:expr) => {{
        let bytes: &mut Aligned<A16, _> = $bytes;
        unsafe { vst1q_u8(bytes[$idx].as_mut_ptr(), $block) };
    }};
}

pub(crate) use store;

macro_rules! xor {
    ($a:expr) => {$a};
    ($a:expr, $b:expr, $c:expr) => {
        unsafe {
            // TODO replace with veor3q_u8 when that's stable
            let mut ret: AesBlock;
            asm!(
                "EOR3 {:v}.16B, {:v}.16B, {:v}.16B, {:v}.16B",
                out(vreg) ret, in(vreg) $a, in(vreg) $b, in(vreg) $c,
            );
            ret
        }
    };
    ($a:expr, $($rest:expr),*) => {
        unsafe { veorq_u8($a, xor!($($rest), *)) }
    };
}

pub(crate) use xor;

macro_rules! enc {
    ($a:expr, $b:expr) => {
       unsafe {
            let z = vmovq_n_u8(0);
            let mut a = $a;
            // TODO replace with vaeseq_u8 and vaesmcq_u8 when that's stable
            asm!(
                "AESE {0:v}.16B, {1:v}.16B",
                "AESMC {0:v}.16B, {0:v}.16B",
                inout(vreg) a, in(vreg) z,
            );
            veorq_u8(a, $b)
       }
    };
}

pub(crate) use enc;
