//! The whole path: sockets, harness, and a real P4 pipeline (spec S13.4 `e2e`).
//!
//! `backends` measures `Engine::process` alone, which answers "what does this
//! backend cost per frame". This answers the question that follows from it:
//! what does the *switch* do, once the pipeline has to share a frame budget
//! with `recvmmsg`, the GRO segment walk, and `sendmmsg`.
//!
//! The two are not the same question. `native` costs tens of nanoseconds
//! against an I/O budget of roughly a microsecond per frame, so it is very
//! nearly free and the harness sets the ceiling. A backend costing microseconds
//! is on the other side of that line, and the ratios here will not match the
//! ratios in `backends`.
//!
//! The fast-path allocation guard of spec S13.5 is a *test*
//! (`benches/tests/alloc_guard.rs`) rather than a bench assertion, so that CI
//! enforces it on every run instead of only when someone benchmarks.

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

/// Frames per offered batch.
const BATCH: usize = 64;

fn e2e(c: &mut Criterion) {
    let mut group = c.benchmark_group("e2e");
    group.sample_size(20);

    for backend in ["native", "x4c", "ubpf"] {
        let mut fixture = benches::loopback::Fixture::start_on("l3fwd", Some(backend), |p| {
            benches::loopback::install_routes(p, 1000)
        });
        for size in [64usize, 1460] {
            let frame = benches::loopback::frame(size, [10, 0, 2, 9]);
            // A batch that does not come back measures the generator, not the
            // switch. Report the recovery once per configuration so a starved
            // run is visible in the output rather than folded into the number.
            let recovered = fixture.round_trip(&frame, BATCH);
            println!("e2e/{backend}/{size}: {recovered}/{BATCH} frames recovered");

            group.throughput(Throughput::Elements(BATCH as u64));
            group.bench_with_input(
                BenchmarkId::new(format!("l3fwd-1k-routes/{backend}"), size),
                &size,
                |b, _| b.iter(|| black_box(fixture.round_trip(&frame, BATCH))),
            );
        }
    }
    group.finish();
}

criterion_group!(benches_group, e2e);
criterion_main!(benches_group);
