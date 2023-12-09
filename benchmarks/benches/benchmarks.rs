#![allow(elided_lifetimes_in_paths)]

use std::io::{self, Read};

use divan::counter::BytesCount;
use lockstitch::{Protocol, TAG_LEN};

const LENS: &[usize] = &[16, 256, 1024, 16 * 1024, 1024 * 1024];

#[divan::bench(consts = LENS)]
fn hash<const LEN: usize>(bencher: divan::Bencher) {
    bencher.with_inputs(|| vec![0u8; LEN]).counter(BytesCount::new(LEN)).bench_refs(|message| {
        let mut protocol = Protocol::new("hash");
        protocol.mix(b"message", message);
        protocol.derive_array::<32>(b"digest")
    });
}

#[divan::bench(consts = LENS)]
fn hash_writer<const LEN: usize>(bencher: divan::Bencher) {
    bencher
        .with_inputs(|| io::repeat(0).take(LEN as u64))
        .counter(BytesCount::new(LEN))
        .bench_values(|mut input| {
            let protocol = Protocol::new("hash");
            let mut writer = protocol.mix_writer(b"message", io::sink());
            io::copy(&mut input, &mut writer).expect("mix writes should be infallible");
            let (mut protocol, _) = writer.into_inner();
            protocol.derive_array::<32>(b"digest")
        });
}

#[divan::bench(consts = LENS)]
fn stream<const LEN: usize>(bencher: divan::Bencher) {
    let key = [0u8; 32];
    let nonce = [0u8; 16];
    bencher.with_inputs(|| vec![0u8; LEN]).counter(BytesCount::new(LEN)).bench_values(
        |mut block| {
            let mut protocol = Protocol::new("stream");
            protocol.mix(b"key", &key);
            protocol.mix(b"nonce", &nonce);
            protocol.encrypt(b"message", &mut block);
            block
        },
    );
}

#[divan::bench(consts = LENS)]
fn aead<const LEN: usize>(bencher: divan::Bencher) {
    let key = [0u8; 32];
    let nonce = [0u8; 16];
    let ad = [0u8; 32];
    bencher.with_inputs(|| vec![0u8; LEN + TAG_LEN]).counter(BytesCount::new(LEN)).bench_values(
        |mut block| {
            let mut protocol = Protocol::new("aead");
            protocol.mix(b"key", &key);
            protocol.mix(b"nonce", &nonce);
            protocol.mix(b"ad", &ad);
            protocol.seal(b"message", &mut block);
            block
        },
    );
}

fn main() {
    divan::main();
}
