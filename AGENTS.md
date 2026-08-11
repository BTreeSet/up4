# AGENTS.md: working in up4

up4 is an unprivileged userspace P4 switch: compiled P4 pipelines over plain
UDP sockets, no root, no async, static TOML topology.

**Artifact of record: [docs/spec.md](docs/spec.md).** On any conflict the spec
wins. Where it is silent, apply its design principles (S3) and ask rather than
invent protocol or semantics. Where the implementation already departs from it,
[docs/deviations.md](docs/deviations.md) says so and why; check there before
"fixing" something that looks wrong.

## Progressive disclosure: read only what the task needs

| Task | Read |
|---|---|
| Anything | this file, then [docs/deviations.md](docs/deviations.md) |
| Any implementation | [docs/spec.md](docs/spec.md) section for your crate + the one milestone plan in [docs/README.md](docs/README.md) |
| Wire format, config, probe | spec S4-S5, S11.1 + [docs/plan/m1](docs/plan/m1-wire-config-probe.md) |
| Sockets, rx/tx, pktgen | spec S6, S7.4, S11.2 + [docs/plan/m2](docs/plan/m2-io-pktgen.md) |
| Ctl channel, counters | spec S8-S9, S12 + [docs/plan/m3](docs/plan/m3-ctl-metrics.md) |
| x4c, adapter, tables, l2fwd | spec S7, S10 + [docs/plan/m4](docs/plan/m4-engine-l2fwd.md) |
| l3fwd, punt | spec S7.2, S8.3, S14 + [docs/plan/m5](docs/plan/m5-l3fwd-punt.md) |
| Cluster runs, benches | spec S13-S14 + [docs/plan/m6](docs/plan/m6-cluster-benches.md) |

Milestones are sequential and each ends runnable. Do not start M(n+1) while
M(n)'s done-when is unmet.

## Hard rules (spec S1; violations are defects, not style issues)

- Unprivileged only. No capabilities, sysctls, ethtool, hugepages, raw
  sockets, TUN/TAP, namespaces, required *or* attempted silently.
- No async runtime anywhere in the datapath. std threads, blocking sockets.
- No forwarding decisions outside the loaded P4 engine (NullEngine oracle
  excepted, benchmarks only).
- Static topology, read once. No discovery, keepalives, negotiation.
- Inner checksums: zero-filled on rewrite, never verified. Nothing else.
- Fail loudly: every discard bumps a named counter; one-time events log WARN.
- `unsafe` only in `up4-io` syscall plumbing (and BPF FFI if activated), each
  block carrying its invariant comment. A7 greps for this.

## Commands

```sh
cargo build --workspace
cargo test --workspace          # incl. conformance corpora and the loopback e2e
cargo clippy --workspace --all-targets -- -D warnings   # must be clean
cargo fmt --check
./scripts/demo.sh               # two routers + two generators, no root
cargo bench -p benches          # fast-path changes only; update benches/RESULTS.md
python3 tools/corpus/gen_corpus.py --check              # corpora are current
```

Definition of done per change: tests green, clippy clean, and, for any
fast-path change, a benchmark delta attached (spec P4). No per-packet
allocation; the e2e counting-allocator guard enforces it.

## Code style (PL-theorist taste, in precedence order)

1. **Correctness and contracts first.** Then totality, then complexity, then
   idiom, then surface elegance. Never trade an earlier rung for a later one.
2. **Make illegal states unrepresentable.** Closed sums as enums with
   exhaustive `match` (`Verdict`, `WireError`, `Fabric`); refined primitives
   as newtypes with private fields and smart constructors (`VportId`,
   `Threads`). No boolean blindness, no sentinel values, no bags of nullables
   encoding a state machine.
3. **Parse, don't validate.** Untrusted bytes (TOML, wire headers, ctl JSON)
   enter through exactly one smart constructor/decoder and become trusted
   domain values. `up4-config` collects *all* violations, not the first.
4. **Pure core, thin shell.** `up4-wire`, `up4-config`, the table shim, and
   verdict mapping are pure and total. Mutation, sockets, clocks, and signals
   live in the `up4-io`/`up4-ctl` shell. The fast path may use local,
   encapsulated mutation and straight-line batch loops; that is the honest
   backend, not a style violation.
5. **Name the cost.** State time/space bounds for non-trivial operations in
   doc comments (demux: O(1) hash lookup; seq tracking: O(1) per packet).
   Preallocated arenas and contiguous descriptors over pointer-chasing; match
   the structure to the dominant access pattern (spec P5).
6. **Modern stable Rust, edition 2024, pinned toolchain.** Prefer `let-else`,
   let chains, one `match` with guards over `if` ladders, the map `Entry` API,
   `is_some_and`/`map_or_else`/`unwrap_or_default` over manual branches.
   Never use features beyond `rust-toolchain.toml`.
7. **Total eliminators.** No `unwrap`, indexing, or `unreachable!` without a
   local proof obvious at the site; encode the proof in a type when practical.
   `Option` for absence, `Result` for expected failure, panics only for
   defects (and release panics abort, spec S12).
8. **Bound everything.** Queues have depths (punt: 1024), batches have caps
   (64), retries happen once (`tx_would_block`). No unbounded anything.

## Dependency policy

Closed list (spec S2): quinn-udp, socket2, libc, serde, serde_json, toml, clap,
tracing, tracing-subscriber, core_affinity, criterion (dev), etherparse
(dev/test only). Anything else needs an in-code TODO citing the spec section
that forces it.

## Explicitly out of scope for v1 (spec S16: refuse, don't build)

Traffic manager/AQM, meters, clone/mirror, recirculation, io_uring
(`// FUTURE(io_uring)` marker only), packet-out, P4Runtime, encryption,
runtime pipeline hot-swap, Windows/macOS.
