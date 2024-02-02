use std::io::{self, Read};

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};
use lockstitch::Protocol;

const LENS: &[(usize, &str)] =
    &[(16, "16B"), (256, "256B"), (1024, "1KiB"), (16 * 1024, "16KiB"), (1024 * 1024, "1MiB")];

fn hash(c: &mut Criterion) {
    let mut g = c.benchmark_group("hash");
    for &(len, id) in LENS {
        let input = vec![0u8; len];
        g.throughput(Throughput::Bytes(len as u64));
        g.bench_with_input(BenchmarkId::from_parameter(id), &input, |b, input| {
            b.iter(|| {
                let mut protocol = Protocol::new("hash");
                protocol.mix("message", input);
                protocol.derive_array::<32>("digest")
            });
        });
    }
    g.finish();
}

fn hash_writer(c: &mut Criterion) {
    let mut g = c.benchmark_group("hash-writer");
    for &(len, id) in LENS {
        g.throughput(Throughput::Bytes(len as u64));
        g.bench_with_input(BenchmarkId::from_parameter(id), &len, |b, &len| {
            b.iter_batched(
                || io::repeat(0u8).take(len as u64),
                |mut input| {
                    let protocol = Protocol::new("hash");
                    let mut writer = protocol.mix_writer("message", io::sink());
                    io::copy(&mut input, &mut writer).expect("should be infallible");
                    let (mut protocol, _) = writer.into_inner();
                    protocol.derive_array::<32>("digest")
                },
                BatchSize::SmallInput,
            );
        });
    }
    g.finish();
}

fn stream(c: &mut Criterion) {
    let key = [0u8; 32];
    let nonce = [0u8; 16];
    let mut g = c.benchmark_group("stream");
    for &(len, id) in LENS {
        g.throughput(Throughput::Bytes(len as u64));
        g.bench_with_input(BenchmarkId::from_parameter(id), &len, |b, &len| {
            b.iter_batched_ref(
                || vec![0u8; len],
                |block| {
                    let mut protocol = Protocol::new("stream");
                    protocol.mix("key", &key);
                    protocol.mix("nonce", &nonce);
                    protocol.encrypt("message", block);
                },
                BatchSize::SmallInput,
            );
        });
    }
    g.finish();
}

fn aead(c: &mut Criterion) {
    let key = [0u8; 32];
    let nonce = [0u8; 16];
    let ad = [0u8; 32];
    let mut g = c.benchmark_group("aead");
    for &(len, id) in LENS {
        g.throughput(Throughput::Bytes(len as u64));
        g.bench_with_input(BenchmarkId::from_parameter(id), &len, |b, &len| {
            b.iter_batched_ref(
                || vec![0u8; len],
                |block| {
                    let mut protocol = Protocol::new("aead");
                    protocol.mix("key", &key);
                    protocol.mix("nonce", &nonce);
                    protocol.mix("ad", &ad);
                    protocol.seal("message", block);
                },
                BatchSize::SmallInput,
            );
        });
    }
    g.finish();
}

fn prf(c: &mut Criterion) {
    let key = [0u8; 32];
    let mut g = c.benchmark_group("prf");
    for &(len, id) in LENS {
        g.throughput(Throughput::Bytes(len as u64));
        g.bench_with_input(BenchmarkId::from_parameter(id), &len, |b, &len| {
            b.iter_batched_ref(
                || vec![0u8; len],
                |block| {
                    let mut protocol = Protocol::new("aead");
                    protocol.mix("key", &key);
                    protocol.derive("output", block);
                },
                BatchSize::SmallInput,
            );
        });
    }
    g.finish();
}

criterion_group!(benches, aead, hash, hash_writer, prf, stream,);
criterion_main!(benches);
