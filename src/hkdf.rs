use sha2::{Digest, Sha256};

/// A streaming version of HKDF-Extract.
#[derive(Debug, Clone)]
pub struct Extract {
    inner_key: [u8; 64],
    outer_key: [u8; 64],
    h: Sha256,
}

impl Extract {
    /// Creates a new [`Extract`] with the given optional salt. Salts should be unique to the
    /// initial keying material, like a nonce.
    #[inline]
    pub fn new(salt: Option<&[u8]>) -> Extract {
        // Prefix the hash with the inner HMAC key.
        let (inner_key, outer_key) = hmac_keys(salt.unwrap_or_default());
        Extract { inner_key, outer_key, h: Sha256::new().chain_update(inner_key) }
    }

    /// Updates the extraction with initial keying material.
    #[inline]
    pub fn update(&mut self, ikm: &[u8]) {
        self.h.update(ikm);
    }

    /// Finalizes the extraction and returns a pseudo-random key for expanding.
    #[inline]
    pub fn finalize_reset(&mut self) -> Prk {
        // Calculate the inner HMAC hash.
        let inner = self.h.finalize_reset();

        // Calculate the outer HMAC hash (aka the PRK).
        self.h.update(self.outer_key);
        self.h.update(inner);
        let prk = self.h.finalize_reset().into();

        // Re-prefix the hash with the inner HMAC key.
        self.h.update(self.inner_key);

        Prk::new(prk)
    }
}

/// A pseudo-random key for HKDF-Expand.
pub struct Prk {
    inner_key: [u8; 64],
    outer_key: [u8; 64],
}

impl Prk {
    #[inline]
    fn new(prk: [u8; 32]) -> Prk {
        let (inner_key, outer_key) = hmac_keys(&prk);
        Prk { inner_key, outer_key }
    }

    /// Fills the given slice with output keying material using the given info slice.
    pub fn expand(&self, info: &[u8], okm: &mut [u8]) {
        const MAX_LEN: usize = 255 * 32;
        assert!(okm.len() <= MAX_LEN, "cannot expand more than {MAX_LEN} bytes");

        let mut h = Sha256::new();
        let mut prev = [0u8; 32];
        for (n, block) in okm.chunks_mut(32).enumerate() {
            // Calculate the inner HMAC hash of the previous block, the info, and a 1-byte counter.
            h.update(self.inner_key);
            if n > 0 {
                h.update(prev);
            }
            h.update(info);
            h.update([n as u8 + 1]);

            // Calculate the outer HMAC hash.
            let inner = h.finalize_reset();
            h.update(self.outer_key);
            h.update(inner);
            prev = h.finalize_reset().into();

            // Use the HMAC as OKM.
            block.copy_from_slice(&prev[..block.len()]);
        }
    }
}

#[inline]
fn hmac_keys(key: &[u8]) -> ([u8; 64], [u8; 64]) {
    let mut inner_key = INNER_KEY;
    let mut outer_key = OUTER_KEY;

    let mut hk = [0u8; 64];
    if key.len() <= 64 {
        hk[..key.len()].copy_from_slice(key);
    } else {
        hk[..32].copy_from_slice(&Sha256::new().chain_update(key).finalize());
    }

    for ((k, i), o) in hk.iter().zip(inner_key.iter_mut()).zip(outer_key.iter_mut()) {
        *i ^= k;
        *o ^= k;
    }

    (inner_key, outer_key)
}

const INNER_KEY: [u8; 64] = [0x36; 64];
const OUTER_KEY: [u8; 64] = [0x5c; 64];

#[cfg(test)]
mod tests {
    use wycheproof::hkdf::{TestFlag, TestName, TestSet};

    use super::*;

    #[test]
    fn wycheproof() {
        let set =
            TestSet::load(TestName::HkdfSha256).expect("should have HKDF-SHA-256 test vectors");
        for group in set.test_groups {
            for test in group.tests {
                if test.flags.contains(&TestFlag::SizeTooLarge) {
                    continue;
                }

                let mut extract = Extract::new(Some(test.salt.as_ref()));
                extract.update(test.ikm.as_ref());
                let prk = extract.finalize_reset();
                let mut okm = vec![0u8; test.size];
                prk.expand(test.info.as_ref(), &mut okm);
            }
        }
    }
}
