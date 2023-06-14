pub use core::arch::aarch64::*;
pub use core::arch::asm;

/// An AES block.
pub use self::uint8x16_t as AesBlock;

/// Create an all-zero AES block.
macro_rules! zero {
    () => {{
        unsafe { vmovq_n_u8(0) }
    }};
}

pub(crate) use zero;

/// Load an AES block from the given slice.
macro_rules! load {
    ($bytes:expr) => {{
        unsafe { vld1q_u8($bytes.as_ptr()) }
    }};
}

pub(crate) use load;

/// Load an AES block from the two given u64 values as big-endian integers.
macro_rules! load_64x2 {
    ($a:expr, $b:expr) => {{
        unsafe { vreinterpretq_u8_u64(vsetq_lane_u64($b, vmovq_n_u64($a), 1)) }
    }};
}

pub(crate) use load_64x2;

/// Store an AES block in the given slice.
macro_rules! store {
    ($bytes:expr, $block:expr) => {{
        unsafe { vst1q_u8($bytes.as_mut_ptr(), $block) };
    }};
}

pub(crate) use store;

/// Bitwise XOR the given AES blocks.
macro_rules! xor {
    ($a:expr, $b:expr) => {{
        unsafe { veorq_u8($a, $b) }
    }};
    ($a:expr, $b:expr, $c:expr) => {{
        unsafe {
            // TODO replace with veor3q_u8 when that's stable
            let mut ret: AesBlock;
            asm!(
                "EOR3 {:v}.16B, {:v}.16B, {:v}.16B, {:v}.16B",
                out(vreg) ret, in(vreg) $a, in(vreg) $b, in(vreg) $c,
            );
            ret
        }
    }};
}

pub(crate) use xor;

/// Bitwise AND the given AES blocks.
macro_rules! and {
    ($a:expr, $b:expr) => {{
        unsafe { vandq_u8($a, $b) }
    }};
}

pub(crate) use and;

/// Perform one AES round on the given state using the given round key.
macro_rules! enc {
    ($state:expr, $round_key:expr) => {{
       unsafe {
            let z = vmovq_n_u8(0);
            let mut a = $state;
            // TODO replace with vaeseq_u8 and vaesmcq_u8 when that's stable
            asm!(
                "AESE {0:v}.16B, {1:v}.16B",
                "AESMC {0:v}.16B, {0:v}.16B",
                inout(vreg) a, in(vreg) z,
            );
            veorq_u8(a, $round_key)
       }
    }};
}

pub(crate) use enc;
