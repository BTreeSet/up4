# M5: l3fwd + punt port

Spec: S7.2 (adapter/checksums), S8.3 (punt), S14 A2-A4.
Done-when: A2, A3, A4 pass on loopback (S15 M5).

## l3fwd

- [ ] `p4/programs/l3fwd/l3fwd.p4`: IPv4 LPM table, TTL decrement, forward to
      vport; 1k-route table population for the perf run.
- [ ] Corpus (S10 minimums + program-specific): TTL=1 (forwards, TTL→0) and
      TTL=0 edge cases, LPM longest-prefix ordering cases (overlapping
      prefixes), hit/miss/default-action, 60 B / 1460 B frames.
- [ ] Checksum zero-fill validated by conformance masking: the mask list is
      exactly IPv4 hdr checksum + L4 checksums; a l3fwd rewrite that misses
      zeroing shows up as a BMv2 diff. If it doesn't, the adapter sniff is
      wrong; fix the adapter, not the mask.

## Punt

- [ ] Program sets egress port 65535 → adapter emits `Verdict::Punt` →
      SPSC queue → `punt-drain`. With `[punt]` absent from config:
      `punt_unconfigured_drop` (S6.3).
- [ ] Integration arm: punt a defined flow, drain via `up4ctl`, assert frame
      bytes + ingress vport + rx timestamp arrive intact.

## Acceptance on loopback

- [ ] A2: ≥ 812 kpps at 1460 B with l3fwd + 1k routes, zero harness drops,
      60 s. Measure and **record** the 64 B ceiling; there is no target, only
      a number to report (A2, README "what you do not get").
- [ ] A3: l2fwd + l3fwd corpora green post-masking.
- [ ] A4: `up4ctl table-add` visible in forwarding ≤ 100 ms after the CLI
      returns; enable the M3 `#[ignore]` test arm.
- [ ] A5 rehearsal: 2× overload, assert `rx_seq_gap_total` + harness drops
      account for ≥ 99% of missing frames.

## Verify

```sh
cargo test --workspace
cargo run --release -p up4d -- --config loopback-a.toml &   # + node b
pktgen --rate-pps 812000 --frame-size 1460 --duration 60 ...
up4ctl --socket /tmp/up4-a.sock table-add ...               # A4 timing
```
