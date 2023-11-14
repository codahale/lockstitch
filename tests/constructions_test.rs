use lockstitch::{Protocol, TAG_LEN};
use quickcheck::{Arbitrary, TestResult};
use quickcheck_macros::quickcheck;

mod message_digest {
    use super::*;

    fn md(domain: &str, m: &[u8]) -> [u8; 32] {
        let mut md = Protocol::new(domain);
        md.mix(b"message", m);
        md.derive_array(b"digest")
    }

    #[quickcheck]
    fn qc_message_digest(d1: String, m1: Vec<u8>, d2: String, m2: Vec<u8>) -> bool {
        let md1 = md(&d1, &m1);
        let md2 = md(&d2, &m2);

        d1 != d2 || m1 != m2 || md1 == md2
    }
}

mod message_authentication_code {
    use super::*;

    fn mac(domain: &str, k: &[u8], m: &[u8]) -> [u8; TAG_LEN] {
        let mut mac = Protocol::new(domain);
        mac.mix(b"key", k);
        mac.mix(b"message", m);
        mac.derive_array::<TAG_LEN>(b"tag")
    }

    #[quickcheck]
    fn qc_message_authentication_code(
        d1: String,
        k1: Vec<u8>,
        m1: Vec<u8>,
        d2: String,
        k2: Vec<u8>,
        m2: Vec<u8>,
    ) -> bool {
        let mac1 = mac(&d1, &k1, &m1);
        let mac2 = mac(&d2, &k2, &m2);

        d1 != d2 || k1 != k2 || m1 != m2 || mac1 == mac2
    }
}

mod stream_cipher {
    use super::*;

    fn enc(domain: &str, k: &[u8], n: &[u8], p: &[u8]) -> Vec<u8> {
        let mut stream = Protocol::new(domain);
        stream.mix(b"key", k);
        stream.mix(b"nonce", n);

        let mut c = p.to_vec();
        stream.encrypt(b"message", &mut c);
        c
    }

    fn dec(domain: &str, k: &[u8], n: &[u8], c: &[u8]) -> Vec<u8> {
        let mut stream = Protocol::new(domain);
        stream.mix(b"key", k);
        stream.mix(b"nonce", n);

        let mut p = c.to_vec();
        stream.decrypt(b"message", &mut p);
        p
    }

    #[quickcheck]
    fn qc_stream_cipher(
        d1: String,
        k1: Vec<u8>,
        n1: Vec<u8>,
        d2: String,
        k2: Vec<u8>,
        n2: Vec<u8>,
        m: Vec<u8>,
    ) -> bool {
        let c = enc(&d1, &k1, &n1, &m);
        let p = dec(&d2, &k2, &n2, &c);

        d1 != d2 || k1 != k2 || n1 != n2 || m == p
    }
}

mod aead {
    use super::*;

    fn ae_enc(domain: &str, k: &[u8], n: &[u8], d: &[u8], p: &[u8]) -> Vec<u8> {
        let mut aead = Protocol::new(domain);
        aead.mix(b"key", k);
        aead.mix(b"nonce", n);
        aead.mix(b"ad", d);

        let mut out = vec![0u8; p.len() + TAG_LEN];
        out[..p.len()].copy_from_slice(p);
        aead.seal(b"message", &mut out);

        out
    }

    fn ae_dec(domain: &str, k: &[u8], n: &[u8], d: &[u8], c: &[u8]) -> Option<Vec<u8>> {
        let mut aead = Protocol::new(domain);
        aead.mix(b"key", k);
        aead.mix(b"nonce", n);
        aead.mix(b"ad", d);

        let mut p = c.to_vec();
        aead.open(b"message", &mut p).map(|p| p.to_vec())
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct AeadParams {
        domain: String,
        key: Vec<u8>,
        nonce: Vec<u8>,
        ad: Vec<u8>,
    }

    impl Arbitrary for AeadParams {
        fn arbitrary(g: &mut quickcheck::Gen) -> Self {
            Self {
                domain: String::arbitrary(g),
                key: Vec::<u8>::arbitrary(g),
                nonce: Vec::<u8>::arbitrary(g),
                ad: Vec::<u8>::arbitrary(g),
            }
        }
    }

    #[quickcheck]
    fn qc_aead(a: AeadParams, b: AeadParams, m: Vec<u8>) -> bool {
        let c = ae_enc(&a.domain, &a.key, &a.nonce, &a.ad, &m);
        let p = ae_dec(&b.domain, &b.key, &b.nonce, &b.ad, &c);

        a != b || p == Some(m)
    }

    #[quickcheck]
    fn qc_aead_mutability(
        d: String,
        k: Vec<u8>,
        n: Vec<u8>,
        ad: Vec<u8>,
        c: Vec<u8>,
    ) -> TestResult {
        if c.len() < TAG_LEN {
            return TestResult::discard();
        }

        TestResult::from_bool(ae_dec(&d, &k, &n, &ad, &c).is_none())
    }
}

mod daead {
    use super::*;

    fn dae_enc(domain: &str, k: &[u8], d: &[u8], p: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; p.len() + TAG_LEN];
        let (iv, ciphertext) = out.split_at_mut(TAG_LEN);
        ciphertext.copy_from_slice(p);

        // Mix in the key and associated data.
        let mut dae = Protocol::new(domain);
        dae.mix(b"key", k);
        dae.mix(b"ad", d);

        // Use a cloned protocol to mix the plaintext and derive a synthetic IV.
        let mut siv = dae.clone();
        siv.mix(b"message", p);
        siv.derive(b"iv", iv);

        // Mix the IV and encrypt the ciphertext.
        dae.mix(b"iv", iv);
        dae.encrypt(b"message", ciphertext);

        out
    }

    fn dae_dec(domain: &str, k: &[u8], d: &[u8], c: &[u8]) -> Option<Vec<u8>> {
        let (iv, ciphertext) = c.split_at(TAG_LEN);
        let mut plaintext = ciphertext.to_vec();

        // Mix in the key and associated data.
        let mut dae = Protocol::new(domain);
        dae.mix(b"key", k);
        dae.mix(b"ad", d);

        // Clone the protocol with just the key and associated data mixed in.
        let mut siv = dae.clone();

        // Mix the IV and decrypt the ciphertext.
        dae.mix(b"iv", iv);
        dae.decrypt(b"message", &mut plaintext);

        // Re-derive the synthetic IV given the unauthenticated plaintext.
        siv.mix(b"message", &plaintext);
        let iv_p = siv.derive_array::<TAG_LEN>(b"iv");

        lockstitch::ct_eq(iv, &iv_p).then_some(plaintext)
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct DaeadParams {
        domain: String,
        key: Vec<u8>,
        ad: Vec<u8>,
    }

    impl Arbitrary for DaeadParams {
        fn arbitrary(g: &mut quickcheck::Gen) -> Self {
            Self {
                domain: String::arbitrary(g),
                key: Vec::<u8>::arbitrary(g),
                ad: Vec::<u8>::arbitrary(g),
            }
        }
    }

    #[quickcheck]
    fn qc_daead(a: DaeadParams, b: DaeadParams, m: Vec<u8>) -> bool {
        let c = dae_enc(&a.domain, &a.key, &a.ad, &m);
        let p = dae_dec(&b.domain, &b.key, &b.ad, &c);

        a != b || p == Some(m)
    }
}

mod tuple_hash {
    use super::*;

    fn tuple_hash(domain: &str, data: &[Vec<u8>]) -> [u8; 32] {
        let mut tuple_hash = Protocol::new(domain);
        for d in data {
            tuple_hash.mix(b"tuple", d);
        }
        tuple_hash.derive_array(b"digest")
    }

    #[quickcheck]
    fn qc_tuple_hash(d1: String, dd1: Vec<Vec<u8>>, d2: String, dd2: Vec<Vec<u8>>) -> bool {
        let h1 = tuple_hash(&d1, &dd1);
        let h2 = tuple_hash(&d2, &dd2);

        d1 != d2 || dd1 != dd2 || h1 == h2
    }
}
