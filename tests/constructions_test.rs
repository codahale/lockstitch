use bolero::TypeGenerator;
use lockstitch::{Protocol, TAG_LEN};

#[test]
fn hash() {
    fn md(domain: &str, m: &[u8]) -> [u8; 32] {
        let mut md = Protocol::new(domain);
        md.mix(b"message", m);
        md.derive_array(b"digest")
    }

    bolero::check!().with_type::<(String, Vec<u8>, String, Vec<u8>)>().for_each(
        |(d1, m1, d2, m2)| {
            let md1 = md(d1, m1);
            let md2 = md(d2, m2);

            if d1 == d2 && m1 == m2 {
                assert_eq!(md1, md2, "equal inputs should produce equal output");
            } else {
                assert_ne!(md1, md2, "non-equal inputs should produce non-equal output");
            }
        },
    );
}

#[test]
fn mac() {
    fn mac(domain: &str, k: &[u8], m: &[u8]) -> [u8; TAG_LEN] {
        let mut mac = Protocol::new(domain);
        mac.mix(b"key", k);
        mac.mix(b"message", m);
        mac.derive_array::<TAG_LEN>(b"tag")
    }

    #[derive(Debug, Clone, PartialEq, Eq, TypeGenerator)]
    struct MacParams {
        domain: String,
        key: Vec<u8>,
    }
    bolero::check!().with_type::<(MacParams, MacParams, Vec<u8>)>().for_each(|(a, b, m)| {
        let t1 = mac(&a.domain, &a.key, m);
        let t2 = mac(&b.domain, &b.key, m);

        if a == b {
            assert_eq!(t1, t2, "equal inputs should produce equal output");
        } else {
            assert_ne!(t1, t2, "non-equal inputs should produce non-equal output");
        }
    });
}

#[test]
fn stream_cipher() {
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

    #[derive(Debug, Clone, PartialEq, Eq, TypeGenerator)]
    struct StreamParams {
        domain: String,
        key: Vec<u8>,
        nonce: Vec<u8>,
    }
    bolero::check!()
        .with_type::<(StreamParams, StreamParams, Vec<u8>)>()
        .filter(|(_, _, m)| m.len() >= 32)
        .for_each(|(a, b, m)| {
            let c = enc(&a.domain, &a.key, &a.nonce, m);
            let p = dec(&b.domain, &b.key, &b.nonce, &c);

            if a == b {
                assert_eq!(&p, m);
            } else {
                assert_ne!(&p, m);
            }
        });
}

#[test]
fn aead() {
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

    #[derive(Debug, Clone, PartialEq, Eq, TypeGenerator)]
    struct AeadParams {
        domain: String,
        key: Vec<u8>,
        nonce: Vec<u8>,
        ad: Vec<u8>,
    }

    bolero::check!().with_type::<(AeadParams, AeadParams, Vec<u8>)>().for_each(|(a, b, m)| {
        let c = ae_enc(&a.domain, &a.key, &a.nonce, &a.ad, m);
        let p = ae_dec(&b.domain, &b.key, &b.nonce, &b.ad, &c);

        if a == b {
            assert_eq!(Some(m.to_vec()), p);
        } else {
            assert_eq!(None, p);
        }
    });
}

#[test]
fn daead() {
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

    #[derive(Debug, Clone, PartialEq, Eq, TypeGenerator)]
    struct DaeadParams {
        domain: String,
        key: Vec<u8>,
        ad: Vec<u8>,
    }
    bolero::check!().with_type::<(DaeadParams, DaeadParams, Vec<u8>)>().for_each(|(a, b, m)| {
        let c = dae_enc(&a.domain, &a.key, &a.ad, m);
        let p = dae_dec(&b.domain, &b.key, &b.ad, &c);

        if a == b {
            assert_eq!(Some(m), p.as_ref());
        } else {
            assert_eq!(None, p);
        }
    });
}

#[test]
fn tuple_hash() {
    type TupleVec = Vec<(Vec<u8>, Vec<u8>)>;

    fn tuple_hash(domain: &str, data: &TupleVec) -> [u8; 32] {
        let mut tuple_hash = Protocol::new(domain);
        for (l, d) in data {
            tuple_hash.mix(l, d);
        }
        tuple_hash.derive_array(b"digest")
    }

    bolero::check!().with_type::<(String, TupleVec, String, TupleVec)>().for_each(
        |(d1, m1, d2, m2)| {
            let h1 = tuple_hash(d1, m1);
            let h2 = tuple_hash(d2, m2);

            if d1 == d2 && m1 == m2 {
                assert_eq!(h1, h2);
            } else {
                assert_ne!(h1, h2);
            }
        },
    );
}
