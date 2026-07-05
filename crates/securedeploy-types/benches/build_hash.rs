use criterion::{black_box, criterion_group, criterion_main, Criterion};
use securedeploy_types::BuildHash;

fn bench_build_hash(c: &mut Criterion) {
    // A representative small artifact chunk.
    let artifact = vec![0xABu8; 4096];
    c.bench_function("build_hash_sha256_4kb", |b| {
        b.iter(|| BuildHash::of(black_box(&artifact)))
    });
}

criterion_group!(benches, bench_build_hash);
criterion_main!(benches);
