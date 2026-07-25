use criterion::{black_box, Criterion};

pub fn bench_framing(c: &mut Criterion) {
    c.bench_function("framing_noop", |b| b.iter(|| black_box(42)));
}

criterion::criterion_group!(benches, bench_framing);
criterion::criterion_main!(benches);
