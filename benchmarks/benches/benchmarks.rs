use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use lockstitch::{Protocol, TAG_LEN};

const LENS: &[(usize, &str)] =
    &[(16, "16B"), (256, "256B"), (1024, "1KiB"), (16 * 1024, "16KiB"), (1024 * 1024, "1MiB")];

fn hash(c: &mut Criterion) {
    let mut g = c.benchmark_group("hash");
    for &(len, id) in LENS {
        let input = vec![0u8; len];
        g.throughput(Throughput::Bytes(len as u64));
        g.bench_function(id, |b| {
            b.iter(|| {
                let mut protocol = Protocol::new("hash");
                protocol.mix("message", &input);
                protocol.derive_array::<32>("digest")
            });
        });
    }
    g.finish();
}

fn stream(c: &mut Criterion) {
    let mut g = c.benchmark_group("stream");
    for &(len, id) in LENS {
        g.throughput(Throughput::Bytes(len as u64));
        g.bench_function(id, |b| {
            let key = [0u8; 32];
            let nonce = [0u8; 16];
            let message = vec![0u8; len];
            b.iter_batched_ref(
                || message.clone(),
                |message| {
                    let mut protocol = Protocol::new("stream");
                    protocol.mix("key", &key);
                    protocol.mix("nonce", &nonce);
                    protocol.encrypt("message", message);
                },
                BatchSize::SmallInput,
            );
        });
    }
    g.finish();
}

fn aead(c: &mut Criterion) {
    let mut g = c.benchmark_group("aead");
    for &(len, id) in LENS {
        g.throughput(Throughput::Bytes(len as u64));
        g.bench_function(id, |b| {
            let key = [0u8; 32];
            let nonce = [0u8; 16];
            let ad = [0u8; 32];
            let message = vec![0u8; len + TAG_LEN];
            b.iter_batched_ref(
                || message.clone(),
                |message| {
                    let mut protocol = Protocol::new("aead");
                    protocol.mix("key", &key);
                    protocol.mix("nonce", &nonce);
                    protocol.mix("ad", &ad);
                    protocol.seal("message", message);
                },
                BatchSize::SmallInput,
            );
        });
    }
    g.finish();
}

fn prf(c: &mut Criterion) {
    let mut g = c.benchmark_group("prf");
    for &(len, id) in LENS {
        g.throughput(Throughput::Bytes(len as u64));
        g.bench_with_input(id, &len, |b, &len| {
            let key = [0u8; 32];
            let output = vec![0u8; len];
            b.iter_batched_ref(
                || output.clone(),
                |output| {
                    let mut protocol = Protocol::new("prf");
                    protocol.mix("key", &key);
                    protocol.derive("output", output);
                },
                BatchSize::SmallInput,
            );
        });
    }
    g.finish();
}

criterion_group!(benches, aead, hash, prf, stream,);
criterion_main!(benches);
