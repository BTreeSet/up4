//! The same program, the same frames, three backends (spec S13.4 `backends`).
//!
//! `engine_only` measures the `native` fast path and is the number that must
//! not regress. This one exists to answer a different question: what does
//! choosing a *compiled* backend cost? It runs every `Program × Backend` pair
//! `up4_catalog::build` admits, over one shared [`Ring`], so the ratios
//! between the three columns are the measurement; the absolute figures are
//! only as portable as the machine.
//!
//! `native` is measured here as well as in `engine_only`, on purpose: it is
//! the baseline the other two are quoted against, and having it in both
//! harnesses is what shows the harnesses agree.
//!
//! What the numbers include is `Engine::process` and its admission check, and
//! nothing else: no sockets, no shard loop. See `benches/RESULTS.md`.

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;
use up4_engine::PipelineParams;
use up4_engine::catalog::{Backend, Program, Selection};

use benches::loopback::{Ring, install_fdb, install_routes};

/// One measured configuration: a program, the control-plane state it needs,
/// and how many distinct destinations the ring cycles through.
struct Case {
    program: Program,
    label: &'static str,
    /// Installed identically on every backend, since the tables are the
    /// program's, not the backend's.
    install: fn(&dyn up4_engine::Pipeline),
    flows: u32,
}

const CASES: &[Case] = &[
    Case {
        program: Program::L2Fwd,
        label: "l2fwd",
        install: install_fdb,
        flows: 16,
    },
    Case {
        program: Program::L3Fwd,
        label: "l3fwd-1-route",
        install: |p| install_routes(p, 1),
        flows: 16,
    },
    Case {
        program: Program::L3Fwd,
        label: "l3fwd-1000-routes",
        install: |p| install_routes(p, 1000),
        flows: 16,
    },
];

fn backends(c: &mut Criterion) {
    let mut group = c.benchmark_group("backends");
    for size in [64usize, 1460] {
        group.throughput(Throughput::Bytes(size as u64));
        for case in CASES {
            for backend in Backend::ALL {
                let pipeline = up4_catalog::build(
                    Selection::P4 {
                        program: case.program,
                        backend,
                    },
                    &PipelineParams::new([0, 1]),
                );
                (case.install)(&*pipeline);
                let mut engine = pipeline.engine();
                let mut ring = Ring::new(size, case.flows);
                group.bench_with_input(
                    BenchmarkId::new(format!("{}/{}", case.label, backend.name()), size),
                    &size,
                    |b, _| b.iter(|| black_box(ring.process(&mut *engine))),
                );
            }
        }
    }
    group.finish();
}

criterion_group!(benches_group, backends);
criterion_main!(benches_group);
