#![allow(elided_lifetimes_in_paths)]

use std::io::{self, Read};

use divan::counter::BytesCount;
use lockstitch::{Protocol, TAG_LEN};

const LENS: &[usize] = &[16, 256, 1024, 16 * 1024, 1024 * 1024];

#[divan::bench(consts = LENS)]
fn hash<const LEN: usize>(bencher: divan::Bencher) {
    bencher.with_inputs(|| vec![0u8; LEN]).counter(BytesCount::new(LEN)).bench_refs(|message| {
        let mut protocol = Protocol::new("hash");
        protocol.mix("message", message);
        protocol.derive_array::<32>("digest")
    });
}

#[divan::bench(consts = LENS)]
fn hash_writer<const LEN: usize>(bencher: divan::Bencher) {
    bencher
        .with_inputs(|| io::repeat(0).take(LEN as u64))
        .counter(BytesCount::new(LEN))
        .bench_values(|mut input| {
            let protocol = Protocol::new("hash");
            let mut writer = protocol.mix_writer("message", io::sink());
            io::copy(&mut input, &mut writer).expect("mix writes should be infallible");
            let (mut protocol, _) = writer.into_inner();
            protocol.derive_array::<32>("digest")
        });
}

#[divan::bench(consts = LENS)]
fn stream<const LEN: usize>(bencher: divan::Bencher) {
    let key = [0u8; 32];
    let nonce = [0u8; 16];
    bencher.with_inputs(|| vec![0u8; LEN]).counter(BytesCount::new(LEN)).bench_values(
        |mut block| {
            let mut protocol = Protocol::new("stream");
            protocol.mix("key", &key);
            protocol.mix("nonce", &nonce);
            protocol.encrypt("message", &mut block);
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
            protocol.mix("key", &key);
            protocol.mix("nonce", &nonce);
            protocol.mix("ad", &ad);
            protocol.seal("message", &mut block);
            block
        },
    );
}

const PRF_LENS: &[usize] = &[16, 256, 1024, 2 * 1024, 4 * 1024];

#[divan::bench(consts = PRF_LENS)]
fn prf<const LEN: usize>(bencher: divan::Bencher) {
    let key = [0u8; 32];
    bencher.with_inputs(|| vec![0u8; LEN]).counter(BytesCount::new(LEN)).bench_values(
        |mut block| {
            let mut protocol = Protocol::new("prf");
            protocol.mix("key", &key);
            protocol.derive("output", &mut block);
            block
        },
    );
}

#[global_allocator]
static ALLOC: divan::AllocProfiler = divan::AllocProfiler::system();

fn main() {
    divan::main();
}
