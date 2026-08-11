//! The whole path: sockets, harness, and a real P4 pipeline (spec S13.4 `e2e`).
//!
//! The fast-path allocation guard of spec S13.5 is a *test*
//! (`benches/tests/alloc_guard.rs`) rather than a bench assertion, so that CI
//! enforces it on every run instead of only when someone benchmarks.

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

fn e2e(c: &mut Criterion) {
    let mut group = c.benchmark_group("e2e");
    group.sample_size(20);
    let mut fixture =
        benches::loopback::Fixture::start("l3fwd", |p| benches::loopback::install_routes(p, 1000));

    for size in [64usize, 1460] {
        let frame = benches::loopback::frame(size, [10, 0, 2, 9]);
        let batch = 64;
        group.throughput(Throughput::Elements(batch as u64));
        group.bench_with_input(BenchmarkId::new("l3fwd-1k-routes", size), &size, |b, _| {
            b.iter(|| black_box(fixture.round_trip(&frame, batch)));
        });
    }
    group.finish();
}

criterion_group!(benches_group, e2e);
criterion_main!(benches_group);
