# M3: up4-ctl + up4-metrics

Spec: S8 (ctl), S9 (metrics), S12 (logging/shutdown).
Done-when: integration test S13.3 passes with NullEngine; counters snapshot
correctly (S15 M3).

## up4-metrics

- [ ] Flat registry of `AtomicU64`, names **exactly** as S9: the
      harness-drop/`engine_drop` separation is a product requirement.
- [ ] Per-vport counter blocks indexed by `VportId`; histograms as fixed
      `[AtomicU64; 7]` bucket arrays (1,2,4,8,16,32,64) + overflow.
- [ ] Snapshot → JSON. Appender thread: if `metrics_interval_s > 0`, one JSON
      line per interval to `up4-metrics-<node>.jsonl`.
- [ ] All hot-path increments `Relaxed`; snapshots use `SeqCst` reads; order
      between counters is explicitly not guaranteed. Document it.

## up4-ctl

- [ ] Unix `SOCK_SEQPACKET` server, one thread, socket created 0600 (S8.1).
      Length-prefixed JSON frames (u32 BE length + serde_json body).
- [ ] Commands (S8.2): `ping`, `info` (build info, pipeline, probe results),
      `counters`, `shutdown` (stop rx → flush tx → final snapshot → exit 0).
      `table-add/del/dump` wired now, returning `engine has no tables` until
      M4 lands the shim: one match arm, not a stub framework.
- [ ] Punt (S8.3): bounded SPSC queue depth 1024, producer = shard thread,
      consumer = ctl thread; full → `punt_overflow_drop`. `punt-drain` returns
      up to N frames base64. Document `packet-out` as v2.
- [ ] `up4ctl` bin: thin clap CLI, 1:1 command mapping, human + `--json`.

## Cross-cutting

- [ ] WARN rate limiter (S12): per-condition-class struct
      `{ count: AtomicU64, last_log: AtomicU64 }`: first occurrence logs,
      then a count line every 10 s. Hand-rolled, ~30 lines, no dep.
- [ ] SIGTERM handling: `sigwait` thread via `libc` lives in **up4-io** (OS
      plumbing; the only place `unsafe` is legal, S1.7), exposing
      `shutdown_signal()`. Invariant comments on every block.
- [ ] Graceful shutdown ordering: stop rx loop → drain staging → final
      snapshot → exit 0 (A6).

## Integration test (S13.3)

- [ ] Two `up4d` processes on loopback, two-node topology, NullEngine;
      pktgen 10 kpps; assert zero harness drops.
- [ ] The table-add visibility half of S13.3 activates in M4 when tables
      exist; leave the test scaffold with a `#[ignore]`-gated arm.

## Verify

```sh
cargo test --workspace          # incl. integration test
./up4ctl --socket /tmp/up4-a.sock counters --json | jq .
```
