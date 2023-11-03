/// An AES block.
pub use aes::Block as AesBlock;

/// Create an all-zero AES block.
#[inline]
pub fn zero() -> AesBlock {
    [0u8; 16].into()
}

/// Load an AES block from the given slice.
#[inline]
pub fn load(bytes: &[u8]) -> AesBlock {
    *AesBlock::from_slice(bytes)
}

/// Load an AES block from the two given u64 values as big-endian integers.
#[inline]
pub fn load_64x2(a: u64, b: u64) -> AesBlock {
    let mut buf = [0u8; core::mem::size_of::<u64>() * 2];
    let (a_block, b_block) = buf.split_at_mut(core::mem::size_of::<u64>());
    a_block.copy_from_slice(&a.to_le_bytes());
    b_block.copy_from_slice(&b.to_le_bytes());
    load(&buf)
}

/// Store an AES block in the given slice.
#[inline]
pub fn store(bytes: &mut [u8], block: AesBlock) {
    bytes.copy_from_slice(&block);
}

/// Bitwise XOR the given AES blocks.
#[inline]
pub fn xor(a: AesBlock, b: AesBlock) -> AesBlock {
    let mut out = AesBlock::default();
    for ((z, x), y) in out.iter_mut().zip(a).zip(b) {
        *z = x ^ y;
    }
    out
}

/// Bitwise XOR the given AES blocks.
#[inline]
pub fn xor3(a: AesBlock, b: AesBlock, c: AesBlock) -> AesBlock {
    let mut out = AesBlock::default();
    for (((z, r), x), y) in out.iter_mut().zip(a).zip(b).zip(c) {
        *z = r ^ x ^ y;
    }
    out
}

/// Bitwise AND the given AES blocks.
#[inline]
pub fn and(a: AesBlock, b: AesBlock) -> AesBlock {
    let mut out = AesBlock::default();
    for ((z, x), y) in out.iter_mut().zip(a).zip(b) {
        *z = x & y;
    }
    out
}

/// Perform one AES round on the given state using the given round key.
#[inline]
pub fn enc(mut state: AesBlock, round_key: AesBlock) -> AesBlock {
    aes::hazmat::cipher_round(&mut state, &round_key);
    state
}
