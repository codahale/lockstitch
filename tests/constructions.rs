use lockstitch::{Protocol, TAG_LEN};
use proptest::collection::vec;
use proptest::prelude::*;

fn md(domain: &str, m: &[u8]) -> [u8; 32] {
    let mut md = Protocol::new(domain);
    md.mix(m);
    md.derive_array()
}

fn mac(domain: &str, k: &[u8], m: &[u8]) -> [u8; TAG_LEN] {
    let mut mac = Protocol::new(domain);
    mac.mix(k);
    mac.mix(m);
    mac.tag_array()
}

fn enc(domain: &str, k: &[u8], n: &[u8], p: &[u8]) -> Vec<u8> {
    let mut stream = Protocol::new(domain);
    stream.mix(k);
    stream.mix(n);

    let mut c = p.to_vec();
    stream.encrypt(&mut c);
    c
}

fn dec(domain: &str, k: &[u8], n: &[u8], c: &[u8]) -> Vec<u8> {
    let mut stream = Protocol::new(domain);
    stream.mix(k);
    stream.mix(n);

    let mut p = c.to_vec();
    stream.decrypt(&mut p);
    p
}

fn ae_enc(domain: &str, k: &[u8], n: &[u8], d: &[u8], p: &[u8]) -> Vec<u8> {
    let mut aead = Protocol::new(domain);
    aead.mix(k);
    aead.mix(n);
    aead.mix(d);

    let mut out = vec![0u8; p.len() + TAG_LEN];
    let (c, t) = out.split_at_mut(p.len());

    c.copy_from_slice(p);
    aead.encrypt(c);

    aead.tag(t);

    out
}

fn ae_dec(domain: &str, k: &[u8], n: &[u8], d: &[u8], c: &[u8]) -> Option<Vec<u8>> {
    let mut aead = Protocol::new(domain);
    aead.mix(k);
    aead.mix(n);
    aead.mix(d);

    let (c, t) = c.split_at(c.len() - TAG_LEN);
    let mut p = c.to_vec();
    aead.decrypt(&mut p);
    aead.check_tag(t).then_some(p)
}

fn tuple_hash(domain: &str, data: &[Vec<u8>]) -> [u8; 32] {
    let mut tuple_hash = Protocol::new(domain);
    for d in data {
        tuple_hash.mix(d);
    }
    tuple_hash.derive_array()
}

proptest! {
    #[test]
    fn message_digests(
        d1: String, m1 in vec(any::<u8>(), 0..200),
        d2: String, m2 in vec(any::<u8>(), 0..200),
    ) {
        let md1 = md(&d1, &m1);
        let md2 = md(&d2, &m2);

        if d1 == d2 && m1 == m2 {
            prop_assert_eq!(md1, md2, "equal inputs produced different outputs");
        } else {
            prop_assert_ne!(md1, md2, "different inputs produced the same outputs");
        }
    }

    #[test]
    fn message_authentication_codes(
        d1: String, k1 in vec(any::<u8>(), 1..200), m1 in vec(any::<u8>(), 1..200),
        d2: String, k2 in vec(any::<u8>(), 1..200), m2 in vec(any::<u8>(), 1..200),
    ) {
        let mac1 = mac(&d1, &k1, &m1);
        let mac2 = mac(&d2, &k2, &m2);

        if d1 == d2 && k1 == k2 && m1 == m2 {
            prop_assert_eq!(mac1, mac2, "equal inputs produced different outputs");
        } else {
            prop_assert_ne!(mac1, mac2, "different inputs produced the same outputs");
        }
    }

    #[test]
    fn stream_ciphers(
        d1: String, k1 in vec(any::<u8>(), 1..200), n1 in vec(any::<u8>(), 1..200),
        d2: String, k2 in vec(any::<u8>(), 1..200), n2 in vec(any::<u8>(), 1..200),
        m in vec(any::<u8>(), 1..200),
    ) {
        let c = enc(&d1, &k1, &n1, &m);
        let p = dec(&d2, &k2, &n2, &c);

        if d1 == d2 && k1 == k2 && n1 == n2 {
            prop_assert_eq!(p, m, "equal inputs produced different outputs");
        } else {
            prop_assert_ne!(p, m, "different inputs produced the same outputs");
        }
    }

    #[test]
    fn aead(
        d1: String, k1 in vec(any::<u8>(), 1..200), n1 in vec(any::<u8>(), 1..200), ad1 in vec(any::<u8>(), 0..200),
        d2: String, k2 in vec(any::<u8>(), 1..200), n2 in vec(any::<u8>(), 1..200), ad2 in vec(any::<u8>(), 0..200),
        m in vec(any::<u8>(), 1..200),
    ) {
        let c = ae_enc(&d1, &k1, &n1, &ad1, &m);
        let p = ae_dec(&d2, &k2, &n2, &ad2, &c);

        if d1 == d2 && k1 == k2 && n1 == n2 && ad1 == ad2 {
            prop_assert_eq!(p, Some(m), "equal inputs produced different outputs");
        } else {
            prop_assert_eq!(p, None, "different inputs produced the same outputs");
        }
    }

    #[test]
    fn aead_mutability(
        d: String,
        k in vec(any::<u8>(), 1..200),
        n in vec(any::<u8>(), 1..200),
        ad in vec(any::<u8>(), 0..200),
        c in vec(any::<u8>(), TAG_LEN..200),
    ) {
        prop_assert_eq!(ae_dec(&d, &k, &n, &ad, &c), None, "decrypted bad ciphertext");
    }

    #[test]
    fn tuple_hashes(
        d1: String, dd1 in vec(vec(any::<u8>(), 0..200), 0..10),
        d2: String, dd2 in vec(vec(any::<u8>(), 0..200), 0..10),
    ) {
        let h1 = tuple_hash(&d1, &dd1);
        let h2 = tuple_hash(&d2, &dd2);

        if d1 == d2 && dd1 == dd2 {
            prop_assert_eq!(h1, h2, "equal inputs produced different outputs");
        } else {
            prop_assert_ne!(h1, h2, "different inputs produced the same outputs");
        }
    }
}
