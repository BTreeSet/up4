//! Pipeline cost with no sockets in the way (spec S13.4 `engine_only`).
//!
//! A preloaded ring of frames goes through `Engine::process` directly, so what
//! is measured is parse + table lookup + rewrite and nothing else.

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;
use up4_engine::PipelineParams;

use benches::loopback::Ring;

fn engines(c: &mut Criterion) {
    let mut group = c.benchmark_group("engine_only");
    for size in [64usize, 1460] {
        group.throughput(Throughput::Bytes(size as u64));

        let l2 = up4_catalog::build(
            up4_engine::catalog::Selection::parse("l2fwd", None).expect("known program"),
            &PipelineParams::new([0, 1]),
        );
        benches::loopback::install_fdb(&*l2);
        let mut l2_engine = l2.engine();
        let mut ring = Ring::new(size, 16);
        group.bench_with_input(BenchmarkId::new("l2fwd", size), &size, |b, _| {
            b.iter(|| black_box(ring.process(&mut *l2_engine)));
        });

        for routes in [1u32, 1000] {
            let l3 = up4_catalog::build(
                up4_engine::catalog::Selection::parse("l3fwd", None).expect("known program"),
                &PipelineParams::new([0, 1]),
            );
            benches::loopback::install_routes(&*l3, routes);
            let mut l3_engine = l3.engine();
            let mut ring = Ring::new(size, 16);
            group.bench_with_input(
                BenchmarkId::new(format!("l3fwd-{routes}-routes"), size),
                &size,
                |b, _| b.iter(|| black_box(ring.process(&mut *l3_engine))),
            );
        }
    }
    group.finish();
}

criterion_group!(benches_group, engines);
criterion_main!(benches_group);
