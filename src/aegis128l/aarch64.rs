pub use core::arch::aarch64::uint8x16_t as AesBlock;
pub use core::arch::aarch64::*;
pub use core::arch::asm;

macro_rules! from_bytes {
    ($bytes:expr) => {{
        let bytes: &[u8] = $bytes;
        vld1q_u8(bytes.as_ptr())
    }};
}

pub(crate) use from_bytes;

macro_rules! as_bytes {
    ($block:expr) => {{
        let mut bytes = Aligned::<A16, _>([0u8; 16]);
        vst1q_u8(bytes.as_mut_ptr(), $block);
        bytes
    }};
}

pub(crate) use as_bytes;

macro_rules! xor {
    ($a:expr) => {$a};
    ($a:expr, $b:expr, $c:expr) => {{
            // TODO replace with veor3q_u8 when that's stable
            let mut ret: AesBlock;
            asm!(
                "EOR3 {:v}.16B, {:v}.16B, {:v}.16B, {:v}.16B",
                out(vreg) ret, in(vreg) $a, in(vreg) $b, in(vreg) $c);
            ret
    }};
    ($a:expr, $($rest:expr),*) => {
        veorq_u8($a, xor!($($rest), *))
    };
}

pub(crate) use xor;

macro_rules! and {
    ($a:expr, $b:expr) => {
        vandq_u8($a, $b)
    };
}

pub(crate) use and;

macro_rules! round {
    ($a:expr, $b:expr) => {{
        let z = vmovq_n_u8(0);
        let mut a = $a;
        // TODO replace with vaeseq_u8 and vaesmcq_u8 when that's stable
        asm!(
            "AESE {0:v}.16B, {1:v}.16B",
            "AESMC {0:v}.16B, {0:v}.16B",
            inout(vreg) a, in(vreg) z);
        veorq_u8(a, $b)
     }};
}

pub(crate) use round;
