# M6 — cluster validation + benches + RESULTS.md

Spec: S13 (testing matrix), S14 (acceptance), S17 (assumptions).
Done-when: A1–A7 on the real cluster, or deviations documented with probe
output attached (S15 M6).

## Benches (criterion, not CI-gating)

- [ ] `engine_only`: preloaded frame ring, no sockets — isolates pipeline cost.
- [ ] `e2e`: full path on loopback; includes the counting-allocator guard —
      zero fast-path allocations over a 1 M-frame run (S13.5). A regression
      here fails the bench, loudly.
- [ ] `benches/RESULTS.md`: table of results with machine description (CPU,
      kernel, NIC, probe JSON attached), one row per bench per run date.
      Committed, not generated in CI.

## Cluster runbook (A1–A7)

- [ ] A1: two nodes, NullEngine, 1 shard, 1460 B, 60 s → ≥ 812 kpps, zero
      harness drops. NIC without GRO/GSO → criterion moves to 4 shards (A1);
      attach probe output either way.
- [ ] A2: l3fwd, 1k routes → ≥ 812 kpps at 1460 B + recorded 64 B ceiling.
- [ ] A3: corpora green in CI (already gated from M4/M5 — re-confirm).
- [ ] A4: table-add visibility ≤ 100 ms, measured cluster-wide.
- [ ] A5: 2× A2 rate overload → loss attribution ≥ 99% via
      `rx_seq_gap_total` + harness drop counters.
- [ ] A6: `kill -TERM` → final snapshot + exit 0; `kill -KILL` one node →
      peer keeps counting rx silence, no crash, no spin.
- [ ] A7: `cargo test` green, `clippy -D warnings` clean, `unsafe` only in
      up4-io syscall plumbing — grep-audit as the final gate:
      `rg -n 'unsafe' crates/ --glob '!crates/up4-io/**'` must be empty.
- [ ] S17: attach probe output for both nodes; every contradicted assumption
      logged as WARN with its fallback, or a documented deviation.

## Verify

```sh
cargo bench --workspace          # update benches/RESULTS.md
rg -n 'unsafe' crates/ --glob '!crates/up4-io/**'   # empty
# then the cluster runbook above, results appended to RESULTS.md
```
