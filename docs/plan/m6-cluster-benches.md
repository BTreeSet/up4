# M6: cluster validation + benches + RESULTS.md

Spec: S13 (testing matrix), S14 (acceptance), S17 (assumptions).
Done-when: A1-A7 on the real cluster, or deviations documented with probe
output attached (S15 M6).

## Benches (criterion, not CI-gating)

- [ ] `engine_only`: preloaded frame ring, no sockets, isolating pipeline cost.
- [ ] `e2e`: full path on loopback; includes the counting-allocator guard:
      zero fast-path allocations over a 1 M-frame run (S13.5). A regression
      here fails the bench, loudly.
- [ ] `benches/RESULTS.md`: table of results with machine description (CPU,
      kernel, NIC, probe JSON attached), one row per bench per run date.
      Committed, not generated in CI.

## Cluster runbook (A1-A7)

- [ ] A1: two nodes, NullEngine, 1 shard, 1460 B, 60 s → ≥ 812 kpps, zero
      harness drops. NIC without GRO/GSO → criterion moves to 4 shards (A1);
      attach probe output either way.
- [ ] A2: l3fwd, 1k routes → ≥ 812 kpps at 1460 B + recorded 64 B ceiling.
- [ ] A3: corpora green in CI (already gated from M4/M5; re-confirm).
- [ ] A4: table-add visibility ≤ 100 ms, measured cluster-wide.
- [ ] A5: 2× A2 rate overload → loss attribution ≥ 99% via
      `rx_seq_gap_total` + harness drop counters.
- [ ] A6: `kill -TERM` → final snapshot + exit 0; `kill -KILL` one node →
      peer keeps counting rx silence, no crash, no spin.
- [ ] A7: `cargo test` green, `clippy -D warnings` clean, and the `unsafe`
      audit passing. **The grep this line used to specify is gone**: generated
      code carries `unsafe impl Send` and the uBPF VM boundary reads memory the
      VM owns, so "empty outside up4-io" became false for good reasons. The
      gate is now `cargo test -p up4d --test unsafe_audit`, which checks every
      site against a warranted allowlist with exact counts
      (see [decisions.md](../decisions.md) ADR-005).
- [ ] S17: attach probe output for both nodes; every contradicted assumption
      logged as WARN with its fallback, or a documented deviation.

## Verify

```sh
cargo bench --workspace          # update benches/RESULTS.md
cargo test -p up4d --test unsafe_audit              # every unsafe site warranted
# then the cluster runbook above, results appended to RESULTS.md
```
