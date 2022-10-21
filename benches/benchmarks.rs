use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use lockstitch::{Protocol, TAG_LEN};

const SIZES: [usize; 5] = [16, 256, 1024, 16 * 1024, 1024 * 1024];
const LABELS: [&str; 5] = ["16B", "256B", "1KiB", "16KiB", "1MiB"];

fn hash(c: &mut Criterion) {
    let mut g = c.benchmark_group("hash");
    for (size, label) in SIZES.into_iter().zip(LABELS) {
        g.throughput(criterion::Throughput::Bytes(size as u64));
        g.bench_function(BenchmarkId::from_parameter(label), |b| {
            let block = vec![0u8; size];
            let mut digest = [0u8; 32];

            b.iter(|| {
                let mut protocol = Protocol::new("hash");
                protocol.mix(&block);
                protocol.derive(&mut digest);
                black_box(&digest);
            });
        });
    }
}

fn prf(c: &mut Criterion) {
    let mut g = c.benchmark_group("prf");
    for (size, label) in SIZES.into_iter().zip(LABELS) {
        g.throughput(criterion::Throughput::Bytes(size as u64));
        g.bench_function(BenchmarkId::from_parameter(label), |b| {
            let key = [0u8; 32];
            let mut block = vec![0u8; size];

            b.iter(|| {
                let mut protocol = Protocol::new("prf");
                protocol.mix(&key);
                protocol.derive(&mut block);
                black_box(&block);
            });
        });
    }
}

fn stream(c: &mut Criterion) {
    let mut g = c.benchmark_group("stream");
    for (size, label) in SIZES.into_iter().zip(LABELS) {
        g.throughput(criterion::Throughput::Bytes(size as u64));
        g.bench_function(BenchmarkId::from_parameter(label), |b| {
            let key = [0u8; 32];
            let nonce = [0u8; 16];
            let mut block = vec![0u8; size];

            b.iter(|| {
                let mut protocol = Protocol::new("stream");
                protocol.mix(&key);
                protocol.mix(&nonce);
                protocol.encrypt(&mut block);
                black_box(&block);
            });
        });
    }
}

fn aead(c: &mut Criterion) {
    let mut g = c.benchmark_group("aead");
    for (size, label) in SIZES.into_iter().zip(LABELS) {
        g.throughput(criterion::Throughput::Bytes(size as u64));
        g.bench_function(BenchmarkId::from_parameter(label), |b| {
            let key = [0u8; 32];
            let nonce = [0u8; 16];
            let ad = [0u8; 32];
            let mut block = vec![0u8; size + TAG_LEN];

            b.iter(|| {
                let mut protocol = Protocol::new("aead");
                protocol.mix(&key);
                protocol.mix(&nonce);
                protocol.mix(&ad);
                protocol.seal(&mut block);
                black_box(&block);
            });
        });
    }
}

criterion_group!(all, hash, prf, stream, aead);
criterion_main!(all);
