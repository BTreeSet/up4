# Benchmark results

Not CI-gating (spec S13.4). Every run below is committed with the machine it
was taken on, because the number without the machine is not a result.

Reproduce with:

```sh
cargo bench -p benches            # engine_only, backends, io_only, e2e
cargo test  -p benches            # the fast-path allocation guard (S13.5)
cargo run -p up4-tools --bin probe -- --peer 127.0.0.1 --pretty
```

---

## 2026-08-11: loopback, aarch64 container

**Machine.** 4 CPUs (cgroup cpuset `0-3`), Linux 6.17.0-35-generic, aarch64.
Loopback only; this is a development box, not the cluster, so these numbers
bound the *harness* and say nothing about a real NIC.

**Probe.**

```json
{"kernel":"6.17.0-35-generic","arch":"aarch64","sockbuf_requested":8388608,
 "rcvbuf_granted":16777216,"sndbuf_granted":16777216,"udp_gro":true,
 "udp_segment":true,"gro_segments":64,"max_gso_segments":64,
 "may_fragment":false,"io_uring_disabled":"0","cpus_available":4,
 "cpuset":"0-3","warnings":[]}
```

### engine_only: pipeline cost, no sockets

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

### io_only: the harness with the pipeline removed

Round trip: generator → shard → generator, 64 segments per batch, null oracle.
The measured loop includes the generator's own send and receive, so the switch
is doing better than these numbers alone show.

| frame | per batch of 64 | frames/s | inner throughput |
|---|---|---|---|
| 64 B | 32.5 µs | 1.97 M | 1.0 Gbps |
| 1460 B | 70.9 µs | 902 k | **10.5 Gbps** |

### e2e: the whole path with a real P4 pipeline

`l3fwd` with 1000 routes installed, same round trip.

| frame | per batch of 64 | frames/s | inner throughput |
|---|---|---|---|
| 64 B | 33.7 µs | 1.90 M | 0.97 Gbps |
| 1460 B | 75.4 µs | 849 k | **9.9 Gbps** |

The pipeline costs about 6% of end-to-end throughput at MTU size, and the
64 B ceiling (the number spec A2 asks to be *reported*, not met) is
**1.9 Mpps** on this box.

Both MTU-size figures clear the 812 kpps that A1 and A2 ask for on loopback
(spec S15 M2, M5). The cluster runs of A1-A7 remain outstanding; see
`docs/plan/m6-cluster-benches.md`.

### Allocation guard (spec S13.5)

`cargo test -p benches` pushes 20 480 frames through the full socket path with
a counting global allocator installed and asserts **zero** allocations. It
passes: after startup, up4's datapath does not allocate.

---

## 2026-08-11 (later): after the three-backend re-architecture

Same box. Re-measured because the pipeline layer changed shape: the name-based
registry became `Program × Backend` and the constructor moved into
`up4-catalog`. The question was whether the `native` backend paid for that.

It did not. `engine_only`, per frame, median:

| pipeline | 64 B | Δ | 1460 B | Δ |
|---|---|---|---|---|
| `l2fwd` | 37.9 ns | -4.9% | 71.5 ns | +2.4% |
| `l3fwd`, 1 route | 30.8 ns | -0.9% | 62.7 ns | -1.5% |
| `l3fwd`, 1000 routes | 34.4 ns | -0.7% | 69.1 ns | +0.3% |

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

---

## 2026-08-11 (later still): all three backends measured

Same box: 4 CPUs (cgroup cpuset `0-3`), Linux 6.17.0-35-generic, **aarch64**,
loopback only. The architecture matters for one row below.

### backends: the same program, the same frames, three ways

`cargo bench -p benches --bench backends`. Per frame, mean, over one shared
ring of 16 destinations. This measures `Engine::process` and the program's
envelope, and nothing else: no sockets, no shard loop.

| program | 64 B | | | 1460 B | | |
|---|---|---|---|---|---|---|
| | `native` | `x4c` | `ubpf` | `native` | `x4c` | `ubpf` |
| `l2fwd` | **37.9 ns** | 4.80 µs | 1.12 µs | **69.4 ns** | 4.93 µs | 1.20 µs |
| `l3fwd`, 1 route | **30.5 ns** | 8.08 µs | 2.62 µs | **63.3 ns** | 8.20 µs | 2.71 µs |
| `l3fwd`, 1000 routes | **35.1 ns** | 297 µs | 2.89 µs | **67.5 ns** | 297 µs | 3.00 µs |

As ratios against `native`, which is the part that travels between machines:

| program | `x4c` | `ubpf` |
|---|---|---|
| `l2fwd` | 127× | 29× |
| `l3fwd`, 1 route | 265× | 86× |
| `l3fwd`, 1000 routes | **8500×** | 82× |

Read the `ubpf` column as the cost of an **interpreter**: this box is aarch64,
where `ExecMode::Jit` does not exist, so every uBPF figure above is
`execute_program`, instruction by instruction. On x86-64 the JIT is the default
(deviations D11) and these numbers do not describe it. That measurement is
still outstanding and is not guessed at here.

The `x4c` column is not an interpreter; it is compiled Rust, and it is the
slowest by a wide margin. Two causes, both upstream and both already declared
rather than discovered: every header field is a heap `BitVec` and the pipeline
returns a `Vec` of outputs per packet (`AllocProfile::PerFrame`, D9), and its
LPM table is searched linearly.

**A thousand routes cost `x4c` 289 µs more per frame than one route**, about
290 ns per installed route, which is a linear scan. At that rate a full
`l3fwd` table is roughly 3.4 kpps. `x4c` is the backend to pick when what
matters is that a real P4 compiler produced real Rust; it is not the backend to
run an experiment through.

### What benchmarking found, before it produced a table

Two of the three columns above are faster than they would have been, because
measuring them turned up defects that reading the code had not:

| | before | after |
|---|---|---|
| `ubpf` `l3fwd`, 1000 routes, 64 B | 7353 ns | **2890 ns** |
| ...its 1000-vs-1-route delta | 4636 ns | **268 ns** |

`Table::longest_prefix` had collected every entry's prefix length into a fresh
`Vec`, sorted it, and deduplicated it *per packet*; the exact path copied the
key image with `to_vec()` just to probe with it. So the uBPF table was O(n log n)
per frame with an allocation, in a backend whose `Backend::facts()` declares
`AllocProfile::None`. Entries are now bucketed by prefix length, kept sorted on
write. The residual 268 ns across 1000 routes is the LPM walking distinct
prefix lengths, which is the intended shape.

The other two findings changed behaviour rather than speed and are recorded in
the commit and in deviations D10: `native` was refusing frames the compiled
backends forwarded, and `native` was zero-filling a transport checksum the
compiled backends left alone, the second hidden by the corpus mask.

### engine_only: no regression in the fast path

| pipeline | 64 B | previous | 1460 B | previous |
|---|---|---|---|---|
| `l2fwd` | 37.2 ns | 37.9 | 69.4 ns | 71.5 |
| `l3fwd`, 1 route | 30.4 ns | 30.8 | 63.4 ns | 62.7 |
| `l3fwd`, 1000 routes | 34.6 ns | 34.4 | 67.9 ns | 69.1 |

Within noise of the previous run and mostly faster. The envelope work added no
cost to `native` because `native` is not wrapped: it already computes both ends
itself, and `up4_catalog::build` composes them only onto the backends that do
not.

### e2e: what the *switch* does, per backend

`cargo bench -p benches --bench e2e`. The whole path: generator → socket →
shard → pipeline → socket → generator, `l3fwd` with 1000 routes, 64 frames per
offered batch. The measured loop includes the generator's own send and receive,
so the switch is doing better than these numbers alone show. Every
configuration recovered 64/64 frames, so these measure the switch and not a
starved generator.

| backend | 64 B | | 1460 B | | vs `native` |
|---|---|---|---|---|---|
| | kpps | Gbps | kpps | Gbps | at 1460 B |
| `native` | **1844** | 0.94 | **856** | **10.0** | 1× |
| `ubpf` (interpreted) | 282 | 0.15 | 229 | 2.67 | 3.7× slower |
| `x4c` | 3.2 | 0.002 | 3.2 | 0.038 | 266× slower |

**The per-frame ratios do not survive contact with the socket path, and that is
the point of measuring both.** `backends` puts `ubpf` at 44× `native` for this
configuration; end to end it is 3.7×. The difference is that every backend pays
the same ~1.17 µs per frame for `recvmmsg`, the GRO segment walk, and
`sendmmsg`, and against that budget `native`'s 67.5 ns pipeline is 6% of the
frame while `ubpf`'s 3.00 µs is 69% of it.

That split is also the answer to whether the uBPF JIT is worth having. A
backend whose pipeline is 6% of the frame budget cannot be helped by making the
pipeline faster, since `native` is I/O-bound and would not move. A backend at
69% is
almost purely pipeline-bound, so time cut from interpretation converts to
throughput at close to 1:1. The JIT has room to recover precisely because the
interpreter does not.

`x4c` is pipeline-bound to the point that **frame size no longer matters**:
19.9 ms per batch at 64 B and at 1460 B alike. At 3.2 kpps the socket path is
idle and the linear LPM scan (D9, ~290 ns per installed route) is the entire
cost. It is a provenance and conformance backend (a real P4 compiler emitting
real Rust, checked against the same corpus) and not a way to carry traffic.

Not measured: `ubpf` under `ExecMode::Jit`. This box is aarch64, where the
variant does not exist. On x86-64 it is the default (D11) and the corpus covers
it, but no throughput figure is quoted for it here.

Also not measured: more than one shard. up4 runs `threads = N` shard threads and
the pipeline is the parallel part, so a pipeline-bound backend should scale with
cores in a way an I/O-bound one does not. That is a plausible mitigation for
`ubpf`, not a measured one, and it is not claimed as a number anywhere.

### What "end to end" does and does not cross

Worth stating precisely, because the phrase invites more credit than the
measurement has earned.

**It does cross the kernel.** `FabricSocket` is an `AF_INET`/`SOCK_DGRAM`
socket; sends and receives are `sendmmsg`/`recvmmsg` through quinn-udp, with
UDP GSO on the way out and GRO on the way in. Every frame goes user → kernel →
user twice. Nothing is short-circuited: the generator and the shard share a
process in this bench, but they are two threads that communicate only through
the socket layer, exactly as two `up4d` instances would. (`crates/up4d/tests/e2e.rs`
does run two separate `up4d` *processes*, but as a correctness test, not a
benchmark.)

**It does not cross a network namespace, a driver, or a wire.** One namespace,
`lo`, MTU 65536. So the path omits the NIC driver, DMA and PCIe, interrupt
handling and coalescing, real 1500-byte segmentation, and any loss or
reordering. On a real NIC the per-frame I/O cost will be different, and not
obviously *higher*, since DMA moves bytes the loopback path memcpys. Which way
it moves is what A1-A7 exist to find out (`docs/plan/m6-cluster-benches.md`);
nothing here should be read as a cluster number.

**Why the backend comparison survives that anyway.** The socket path is a
common-mode term: all three backends pay it identically, so it adds to each
frame budget rather than scaling it. `io_only` is the same path with the
pipeline removed entirely, and at 1460 B it is indistinguishable from `native`
carrying a full 1000-route `l3fwd`:

| | per batch of 64 | per frame |
|---|---|---|
| `io_only`, no pipeline at all | 74.9 µs | 1.170 µs |
| `e2e`, `native` + 1000-route `l3fwd` | 74.8 µs | 1.168 µs |

The confidence intervals overlap almost completely. At MTU size up4's P4
pipeline on `native` is **free**: the switch runs at the speed of its socket
layer, and a faster pipeline could not make it quicker.

That decomposition is what makes the rest transportable. Frame budget is
`io + pipeline`; this box measures `io ≈ 1.17 µs` at 1460 B, and the per-frame
pipeline costs are in the `backends` table. Anyone with a different `io` can
substitute it and re-derive the split, including the share-of-budget argument
about the uBPF JIT, which is 69% on loopback and would fall as `io` rises.
The *structure* of that argument is robust; the specific percentage is not.

