//! The harness with the pipeline removed (spec S13.4 `io_only`).
//!
//! The null oracle decides in one array read, so what this measures is the
//! receive batch, the GRO segment walk, the staging copy, and the GSO write.

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

fn io(c: &mut Criterion) {
    let mut group = c.benchmark_group("io_only");
    group.sample_size(20);
    let mut fixture = benches::loopback::Fixture::start("null", |_| {});

    for size in [64usize, 1460] {
        let frame = benches::loopback::frame(size, [10, 0, 2, 9]);
        let batch = 64;
        group.throughput(Throughput::Elements(batch as u64));
        group.bench_with_input(BenchmarkId::new("batch64", size), &size, |b, _| {
            b.iter(|| black_box(fixture.round_trip(&frame, batch)));
        });
    }
    group.finish();
}

criterion_group!(benches_group, io);
criterion_main!(benches_group);
