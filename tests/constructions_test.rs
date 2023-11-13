use lockstitch::{Protocol, TAG_LEN};
use proptest::collection::vec;
use proptest::prelude::*;

fn md(domain: &str, m: &[u8]) -> [u8; 32] {
    let mut md = Protocol::new(domain);
    md.mix(b"message", m);
    md.derive_array(b"digest")
}

fn mac(domain: &str, k: &[u8], m: &[u8]) -> [u8; TAG_LEN] {
    let mut mac = Protocol::new(domain);
    mac.mix(b"key", k);
    mac.mix(b"message", m);
    mac.derive_array::<TAG_LEN>(b"tag")
}

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

fn tuple_hash(domain: &str, data: &[Vec<u8>]) -> [u8; 32] {
    let mut tuple_hash = Protocol::new(domain);
    for d in data {
        tuple_hash.mix(b"tuple", d);
    }
    tuple_hash.derive_array(b"digest")
}

proptest! {
    #[test]
    fn message_digests(
        d1: String, m1 in vec(any::<u8>(), 0..200),
        d2: String, m2 in vec(any::<u8>(), 0..200),
    ) {
        prop_assume!(!(d1 == d2 && m1 == m2), "inputs must be different");

        let md1 = md(&d1, &m1);
        let md2 = md(&d2, &m2);

        prop_assert_ne!(md1, md2, "different inputs produced the same outputs");
    }

    #[test]
    fn message_authentication_codes(
        d1: String, k1 in vec(any::<u8>(), 1..200), m1 in vec(any::<u8>(), 1..200),
        d2: String, k2 in vec(any::<u8>(), 1..200), m2 in vec(any::<u8>(), 1..200),
    ) {
        prop_assume!(!(d1 == d2 && k1 == k2 && m1 == m2), "inputs must be different");

        let mac1 = mac(&d1, &k1, &m1);
        let mac2 = mac(&d2, &k2, &m2);

        prop_assert_ne!(mac1, mac2, "different inputs produced the same outputs");
    }

    #[test]
    fn stream_ciphers(
        d1: String, k1 in vec(any::<u8>(), 1..200), n1 in vec(any::<u8>(), 1..200),
        d2: String, k2 in vec(any::<u8>(), 1..200), n2 in vec(any::<u8>(), 1..200),
        m in vec(any::<u8>(), 100..200),
    ) {
        prop_assume!(!(d1 == d2 && k1 == k2 && n1 == n2), "inputs must be different");

        let c = enc(&d1, &k1, &n1, &m);
        let p = dec(&d2, &k2, &n2, &c);

        prop_assert_ne!(p, m, "different inputs produced the same outputs");
    }

    #[test]
    fn aead(
        d1: String, k1 in vec(any::<u8>(), 1..200), n1 in vec(any::<u8>(), 1..200), ad1 in vec(any::<u8>(), 0..200),
        d2: String, k2 in vec(any::<u8>(), 1..200), n2 in vec(any::<u8>(), 1..200), ad2 in vec(any::<u8>(), 0..200),
        m in vec(any::<u8>(), 1..200),
    ) {
        prop_assume!(!(d1 == d2 && k1 == k2 && n1 == n2 && ad1 == ad2), "inputs must be different");

        let c = ae_enc(&d1, &k1, &n1, &ad1, &m);
        let p = ae_dec(&d2, &k2, &n2, &ad2, &c);

        prop_assert_eq!(p, None, "different inputs produced the same outputs");
    }

    #[test]
    fn aead_mutability(
        d: String,
        k in vec(any::<u8>(), 1..200),
        n in vec(any::<u8>(), 1..200),
        ad in vec(any::<u8>(), 0..200),
        c in vec(any::<u8>(), TAG_LEN..200),
    ) {
        let p = ae_dec(&d, &k, &n, &ad, &c);

        prop_assert_eq!(p, None, "decrypted bad ciphertext");
    }

    #[test]
    fn dae(
        d1: String, k1 in vec(any::<u8>(), 1..200), ad1 in vec(any::<u8>(), 0..200),
        d2: String, k2 in vec(any::<u8>(), 1..200), ad2 in vec(any::<u8>(), 0..200),
        m in vec(any::<u8>(), 1..200),
    ) {
        prop_assume!(!(d1 == d2 && k1 == k2 && ad1 == ad2), "inputs must be different");

        let c = dae_enc(&d1, &k1, &ad1, &m);
        let p = dae_dec(&d2, &k2, &ad2, &c);

        prop_assert_eq!(p, None, "different inputs produced the same outputs");
    }

    #[test]
    fn dae_mutability(
        d: String,
        k in vec(any::<u8>(), 1..200),
        ad in vec(any::<u8>(), 0..200),
        c in vec(any::<u8>(), TAG_LEN..200),
    ) {
        let p = dae_dec(&d, &k, &ad, &c);

        prop_assert_eq!(p, None, "decrypted bad ciphertext");
    }

    #[test]
    fn tuple_hashes(
        d1: String, dd1 in vec(vec(any::<u8>(), 0..200), 0..10),
        d2: String, dd2 in vec(vec(any::<u8>(), 0..200), 0..10),
    ) {
        prop_assume!(!(d1 == d2 && dd1 == dd2), "inputs must be different");

        let h1 = tuple_hash(&d1, &dd1);
        let h2 = tuple_hash(&d2, &dd2);

        prop_assert_ne!(h1, h2, "different inputs produced the same outputs");
    }
}
