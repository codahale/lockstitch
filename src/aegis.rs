mod aegis_128l;
mod aegis_256;

pub use self::aegis_128l::Aegis128L;
pub use self::aegis_256::Aegis256;

/// A wrapper trait for the AEGIS-128L and AEGIS-256 implementations.
pub trait Aegis {
    /// Encrypts the given slice in place.
    fn encrypt(&mut self, in_out: &mut [u8]);

    /// Decrypts the given slice in place.
    fn decrypt(&mut self, in_out: &mut [u8]);

    /// Finalizes the cipher state into a pair of 128-bit and 256-bit authentication tags.
    fn finalize(self) -> ([u8; 16], [u8; 32]);
}
