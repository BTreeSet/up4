# M2 — up4-io + NullEngine + pktgen

Spec: S6 (I/O), S7.1/S7.4 (engine trait, oracle), S11.2 (pktgen).
Done-when: A1 achievable on loopback — ≥ 812 kpps at 1460 B, 60 s, zero
harness drops; record the number (S15 M2).

## up4-engine (trait only, no x4c yet)

- [ ] `Verdict`, `FrameCtx`, `Engine` exactly as S7.1. Closed enum, no
      engine-allocated state in the verdict path.
- [ ] `NullEngine` behind `--features oracle`, excluded from default builds:
      `Forward(1 - ingress)` for two-port configs, config-selected static map
      otherwise (S7.4).
- [ ] `mod fallback_ubpf;` — skeleton + doc comment only (S7.5).

## up4-io

- [ ] **First task:** pin `quinn-udp` and read its actual batch recv/send API
      (`UdpSocketState`, `RecvMeta.stride`, GSO `Transmit`). Write the loops
      against the real signatures, not this plan's guesses.
- [ ] Socket builder (S6.1): socket2; `SO_REUSEPORT` when threads > 1;
      request 8 MiB RCVBUF/SNDBUF, read back and log **granted** values;
      one `UdpSocketState` per socket; log `gro/gso/max_gso_segments` once.
- [ ] Rx loop (S6.2): arena of 64 slots allocated once, each sized
      `max_udp_payload_size() * gro_segments()` from quinn-udp (~92 KiB on
      Linux) — not a hardcoded 64 KiB; batched recv; GRO
      stride iteration; demux via the config-built `HashMap`; decode; seq
      accounting (per-vport `expected_seq`, gap accumulate, reorder window
      1024, record-only); engine invoke; oversize check.
- [ ] Tx path (S6.3): per-vport staging = preallocated `Vec<SegDesc>` (arena
      offset+len), cleared per batch; headers stamped at send time (seq/ts);
      GSO when segments share dest + size class, else `sendmmsg` batching;
      partial send → retry remainder once → `tx_would_block`.
- [ ] `// FUTURE(io_uring)` marker at the send/recv abstraction (S6.4). No
      cross-thread handoff; a frame lives and dies on one thread.
- [ ] No per-packet heap allocation anywhere in either path.

## pktgen (tools crate, bin `pktgen`)

- [ ] clap: `--frame-size`, `--rate-pps` (token bucket, 0 = max), `--flows`
      (vary inner src/dst), `--duration`, target node address.
- [ ] Receiver side: seq checking per sender vport; loss from seq gaps.
- [ ] Report: achieved pps/Gbps, loss, p50/p99 one-way latency from `ts_us`.
      Latency histogram = sorted `Vec<i64>` of samples, percentiles by index —
      no hdrhistogram dep. Cross-host runs labeled "uncalibrated clock delta".

## benches (crate `benches`)

- [ ] Counting-allocator guard harness (shared by all later benches).
- [ ] `io_only`: NullEngine echo on loopback through the real rx/tx path.

## Decisions

- Staging is a plain preallocated `Vec` (S6.3): batch-bounded capacity means
  it never grows after startup.
- The engine instance lives on the shard thread stack; tables arrive in M4.

## Verify

```sh
cargo build --release --features oracle
cargo test -p up4-io
cargo bench -p benches -- io_only   # record loopback number in the commit
```
