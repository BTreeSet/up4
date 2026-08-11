# up4-x4c

The `x4c` backend: `p4/programs/*/*.softnpu.p4` compiled to Rust by Oxide's
[x4c](https://github.com/oxidecomputer/p4), adapted onto up4's contracts.

## Why this is a crate of its own

`up4-engine` is `#![forbid(unsafe_code)]`. x4c's output is not — it emits
`unsafe impl Send for main_pipeline`. A crate-level `forbid` cannot be relaxed
per module, so generated code cannot live in the engine without giving up the
property that makes the engine worth trusting. It lives here instead, where the
exception is named, bounded, and on the allowlist
(`crates/up4d/tests/unsafe_audit.rs`).

## What to know

`src/generated/` is compiler output. Do not edit it: `cargo xtask verify` checks
it against its `.p4` source, and a hand edit would be reported as staleness.
Regenerate with `cargo xtask generate`.

`p4rs` (x4c's runtime) is pinned by git revision to the same commit the
compiler is built from. Generated code and its runtime are one artifact;
letting them drift would be a silent miscompile.

This backend allocates on the fast path — x4c models header fields as heap
`BitVec` and returns a `Vec` per packet. That is not a defect to be fixed here;
it is a property of the compiler, declared in `Backend::facts()` so the binary
reports it and the documentation never has to remember to.
