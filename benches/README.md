# benches

Criterion benchmarks and the fast-path allocation guard. Not CI-gating (spec
S13.4) — numbers without the machine they were taken on are not results, so
`RESULTS.md` records both.

`src/lib.rs` holds a counting global allocator. That is the one `unsafe` outside
`crates/`, and it exists to prove a claim rather than to make one: `cargo test
-p benches` pushes frames through the full socket path and fails if the fast
path allocated even once.
