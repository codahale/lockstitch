pub use aes::Block as AesBlock;

macro_rules! zero {
    () => {{
        [0u8; 16].into()
    }};
}

pub(crate) use zero;

macro_rules! load {
    ($bytes:expr) => {{
        *AesBlock::from_slice($bytes)
    }};
}

pub(crate) use load;

macro_rules! load_64x2 {
    ($a:expr, $b:expr) => {{
        let mut buf = [0u8; core::mem::size_of::<u64>() * 2];
        let (a_block, b_block) = buf.split_at_mut(core::mem::size_of::<u64>());
        a_block.copy_from_slice(&$a.to_le_bytes());
        b_block.copy_from_slice(&$b.to_le_bytes());
        load!(&buf)
    }};
}

pub(crate) use load_64x2;

macro_rules! store {
    ($bytes:expr, $block:expr) => {{
        $bytes.copy_from_slice(&$block);
    }};
}

pub(crate) use store;

macro_rules! xor {
    ($a:expr, $b:expr) => {{
        xor_block($a, $b)
    }};
    ($a:expr, $b:expr, $c:expr) => {{
        xor_block($a, xor!($b, $c))
    }};
}

pub(crate) use xor;

#[inline(always)]
pub fn xor_block(a: AesBlock, b: AesBlock) -> AesBlock {
    let mut out = AesBlock::default();
    for ((z, x), y) in out.iter_mut().zip(a).zip(b) {
        *z = x ^ y;
    }
    out
}

macro_rules! and {
    ($a:expr, $b:expr) => {{
        and_block($a, $b)
    }};
}

pub(crate) use and;

#[inline(always)]
pub fn and_block(a: AesBlock, b: AesBlock) -> AesBlock {
    let mut out = AesBlock::default();
    for ((z, x), y) in out.iter_mut().zip(a).zip(b) {
        *z = x & y;
    }
    out
}

macro_rules! enc {
    ($a:expr, $b:expr) => {{
        let mut out = $a;
        aes::hazmat::cipher_round(&mut out, &$b);
        out
    }};
}

pub(crate) use enc;
