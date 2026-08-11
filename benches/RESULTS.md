# Benchmark results

Not CI-gating (spec S13.4). Every run below is committed with the machine it
was taken on, because the number without the machine is not a result.

Reproduce with:

```sh
cargo bench -p benches            # engine_only, io_only, e2e
cargo test  -p benches            # the fast-path allocation guard (S13.5)
cargo run -p up4-tools --bin probe -- --peer 127.0.0.1 --pretty
```

---

## 2026-08-11 — loopback, aarch64 container

**Machine.** 4 CPUs (cgroup cpuset `0-3`), Linux 6.17.0-35-generic, aarch64.
Loopback only — this is a development box, not the cluster, so these numbers
bound the *harness* and say nothing about a real NIC.

**Probe.**

```json
{"kernel":"6.17.0-35-generic","arch":"aarch64","sockbuf_requested":8388608,
 "rcvbuf_granted":16777216,"sndbuf_granted":16777216,"udp_gro":true,
 "udp_segment":true,"gro_segments":64,"max_gso_segments":64,
 "may_fragment":false,"io_uring_disabled":"0","cpus_available":4,
 "cpuset":"0-3","warnings":[]}
```

### engine_only — pipeline cost, no sockets

Per frame, median. The harness copies a fresh frame into the buffer each
iteration, so the 1460 B rows carry roughly 30 ns of `memcpy` that the switch
itself does not pay twice; the 64 B rows are the closest thing to pipeline cost
alone.

| pipeline | 64 B | 1460 B |
|---|---|---|
| `l2fwd` (exact match on MAC) | 40.0 ns | 69.9 ns |
| `l3fwd`, 1 route | 30.9 ns | 63.7 ns |
| `l3fwd`, 1000 routes | 34.7 ns | 69.1 ns |

A thousand routes cost **3.8 ns** more per frame than one. That is the
prefix-length-grouped LPM doing what it was chosen to do: the probe count
follows the number of *distinct prefix lengths* (one, here), not the number of
routes.

### io_only — the harness with the pipeline removed

Round trip: generator → shard → generator, 64 segments per batch, null oracle.
The measured loop includes the generator's own send and receive, so the switch
is doing better than these numbers alone show.

| frame | per batch of 64 | frames/s | inner throughput |
|---|---|---|---|
| 64 B | 32.5 µs | 1.97 M | 1.0 Gbps |
| 1460 B | 70.9 µs | 902 k | **10.5 Gbps** |

### e2e — the whole path with a real P4 pipeline

`l3fwd` with 1000 routes installed, same round trip.

| frame | per batch of 64 | frames/s | inner throughput |
|---|---|---|---|
| 64 B | 33.7 µs | 1.90 M | 0.97 Gbps |
| 1460 B | 75.4 µs | 849 k | **9.9 Gbps** |

The pipeline costs about 6% of end-to-end throughput at MTU size, and the
64 B ceiling — the number spec A2 asks to be *reported*, not met — is
**1.9 Mpps** on this box.

Both MTU-size figures clear the 812 kpps that A1 and A2 ask for on loopback
(spec S15 M2, M5). The cluster runs of A1–A7 remain outstanding; see
`docs/plan/m6-cluster-benches.md`.

### Allocation guard (spec S13.5)

`cargo test -p benches` pushes 20 480 frames through the full socket path with
a counting global allocator installed and asserts **zero** allocations. It
passes: after startup, up4's datapath does not allocate.

---

## 2026-08-11 (later) — after the three-backend re-architecture

Same box. Re-measured because the pipeline layer changed shape: the name-based
registry became `Program × Backend` and the constructor moved into
`up4-catalog`. The question was whether the `native` backend paid for that.

It did not. `engine_only`, per frame, median:

| pipeline | 64 B | Δ | 1460 B | Δ |
|---|---|---|---|---|
| `l2fwd` | 37.9 ns | −4.9% | 71.5 ns | +2.4% |
| `l3fwd`, 1 route | 30.8 ns | −0.9% | 62.7 ns | −1.5% |
| `l3fwd`, 1000 routes | 34.4 ns | −0.7% | 69.1 ns | +0.3% |

Every figure is within ±2.5% of the previous run and most moved the right way,
which is what "no cost" looks like at this scale rather than an exactly equal
number. The selection is resolved once at startup and the shard loop still
holds a `Box<dyn Engine>` it calls directly, so there was no new indirection
for the change to add.

A thousand routes still cost **3.6 ns** more per frame than one (3.8 ns
before): the prefix-length-grouped LPM continues to probe per distinct prefix
length, not per route.

The `x4c` and `ubpf` backends are not measured here yet. Both are correct
against the shared corpus; neither has a number, and the honest thing is to
leave that blank rather than quote a figure taken from a debug build.
