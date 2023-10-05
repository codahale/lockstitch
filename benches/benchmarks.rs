use divan::counter::BytesCount;
use lockstitch::{Protocol, TAG_LEN};

const LENS: &[usize] = &[16, 256, 1024, 16 * 1024, 1024 * 1024];

fn main() {
    divan::main()
}

#[divan::bench(consts = LENS)]
fn hash<const LEN: usize>(bencher: divan::Bencher) {
    bencher.with_inputs(|| vec![0u8; LEN]).counter(BytesCount::new(LEN)).bench_refs(|block| {
        let mut digest = [0u8; 32];
        let mut protocol = Protocol::new("hash");
        protocol.mix(block);
        protocol.derive(&mut digest);
        digest
    });
}

#[divan::bench(consts = LENS)]
fn prf<const LEN: usize>(bencher: divan::Bencher) {
    let key = [0u8; 32];
    bencher.with_inputs(|| vec![0u8; LEN]).counter(BytesCount::new(LEN)).bench_values(
        |mut block| {
            let mut protocol = Protocol::new("prf");
            protocol.mix(&key);
            protocol.derive(&mut block);
        },
    );
}

#[divan::bench(consts = LENS)]
fn stream<const LEN: usize>(bencher: divan::Bencher) {
    let key = [0u8; 32];
    let nonce = [0u8; 16];
    bencher.with_inputs(|| vec![0u8; LEN]).counter(BytesCount::new(LEN)).bench_values(
        |mut block| {
            let mut protocol = Protocol::new("stream");
            protocol.mix(&key);
            protocol.mix(&nonce);
            protocol.encrypt(&mut block);
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
            protocol.mix(&key);
            protocol.mix(&nonce);
            protocol.mix(&ad);
            protocol.seal(&mut block);
        },
    );
}
