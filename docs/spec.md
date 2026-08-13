# up4 Implementation Specification

**Version:** 1.0 (implementation handoff)
**Audience:** coding agent performing full implementation. This document is
self-contained; do not assume access to prior discussion. Where this spec is
silent, prefer the Design Principles (S3) and ask rather than invent protocol
or semantics.

---

## S0. One-paragraph summary

up4 is an unprivileged userspace P4 switch. Each instance is a single Linux
process exposing virtual ports (vports). A vport is a UDP flow to a peer
instance, defined by a static TOML topology file. Inner packets are full
Ethernet frames carried as UDP payloads behind a fixed 12-byte overlay header.
All forwarding decisions are made by a compiled P4 pipeline (x4c-generated
Rust) invoked per frame; the harness never makes forwarding decisions. Target:
~9.5 Gbps of inner traffic at 1460 B frames on one core, zero root privileges,
default kernel settings.

## S1. Hard constraints (violating any of these is a defect)

1. **No privileges.** The binary must run as an ordinary user. Never require
   capabilities, sysctl changes, ethtool, hugepages, raw sockets, TUN/TAP, or
   network namespaces. Never attempt them silently either: optional features
   are probed, and probe results are logged.

   This constrains the **system under test**, not the harness that builds a
   topology around it. A test rig may create containers or namespaces to
   simulate two machines; what it may not do is run up4's binaries with any
   privilege they would not have in the field. The distinction is mechanical,
   not editorial: the harness lives outside `crates/`, and any multi-host run
   asserts `euid != 0` for every up4 process before it starts. See
   [decisions.md](decisions.md) ADR-007 and [plan/m7](plan/m7-multihost.md).
2. **No async runtime.** std threads and blocking sockets only. No tokio,
   async-std, smol, or mio in the datapath.
3. **No forwarding logic in harness code.** The only component that may decide
   an output port or modify inner headers is the loaded P4 engine (exception:
   the `null` oracle engine, S7.4, which exists for benchmarks only).
4. **No dynamic topology.** Config is read once at startup. No discovery, no
   keepalives, no negotiation, no in-band control messages.
5. **No inner checksum computation or verification.** Inner IPv4/TCP/UDP
   checksums are zero-filled whenever the pipeline modifies the containing
   header, and are never validated. (Outer UDP checksum covers integrity.)
6. **Fail loudly.** Every discard, refusal, or fallback increments a named
   counter and, for one-time events, logs at WARN.
7. **MSRV:** latest stable Rust at implementation time; pin in
   `rust-toolchain.toml`. `unsafe` allowed only in `up4-io` syscall
   plumbing and (if activated) BPF FFI, each block commented with its
   invariant.

## S2. Repository layout

```
up4/
  Cargo.toml                # workspace
  rust-toolchain.toml
  crates/
    up4-wire/               # overlay header encode/decode, constants (no I/O)
    up4-config/             # TOML schema, validation, topology model
    up4-engine/             # Engine trait, verdicts, x4c adapter, null oracle
    up4-io/                 # sockets, batching, GSO/GRO, rx/tx loops
    up4-ctl/                # control side-channel server + up4ctl client bin
    up4-metrics/            # counters, histograms, snapshot serialization
    up4d/                   # main binary: wiring, startup probes, lifecycle
  p4/
    programs/<name>/<name>.p4
    corpus/<name>/*.json    # conformance corpus (S10)
  tools/
    probe.rs                # cluster capability probe (S11.1)
    pktgen.rs               # load generator (S11.2)
    bmv2-diff/              # conformance runner scripts (python, CI only)
  benches/                  # criterion benches: io_only, engine_only, e2e
```

Dependencies (workspace): `quinn-udp`, `socket2`, `libc`, `serde`, `serde_json`
(S8/S9/S11.1 all mandate JSON output), `toml`, `clap`, `tracing`,
`tracing-subscriber`, `core_affinity`, `criterion` (dev), `etherparse`
(dev/test only). x4c-generated code is vendored into
`up4-engine/src/gen/<program>.rs` by a build step invoking `x4c` (pin the x4c
git revision in a build script constant). Do not add dependencies beyond this
list without an explicit TODO comment explaining why.

## S3. Design principles (tie-breakers for anything unspecified)

P1 P4 source is the artifact of record. P2 Unprivileged means unprivileged.
P3 Fail loudly, degrade explicitly. P4 Measure before optimizing: no fast-path
change without a benchmark delta. P5 Static and boring beats clever: prefer
preallocated fixed-size structures, `#[repr(C)]` where layout matters, and
straight-line batch loops over abstraction.

## S4. Wire format (`up4-wire`)

Outer packet = cluster IPv4/UDP (kernel-provided) + overlay header + inner
Ethernet frame.

Overlay header, 12 bytes, all multi-byte fields big-endian:

```
offset  size  field
0       1     ver_flags   high nibble version = 0x1; low nibble flags, all 0 in v1
1       1     rsvd        must send 0; receiver ignores
2       2     ingress_vport  sender-side vport id (tracing only; receiver
                             derives ingress from source tuple, S6)
4       4     seq         per (sender, vport) monotonically increasing, wraps
8       4     ts_us       sender CLOCK_MONOTONIC microseconds, truncated u32
```

Constants: `OVERLAY_HDR_LEN = 12`, `INNER_MTU = 1460` (IPv4 fabric) or `1440`
(IPv6 fabric, selected by config `fabric = "ipv4" | "ipv6"`; default ipv4).
Encode/decode must be branch-light and alloc-free; provide
`fn encode(hdr, &mut [u8;12])` and `fn decode(&[u8]) -> Result<Hdr, WireError>`.
Reject: wrong version, short buffer. Unit-test all rejects and a round-trip
property test.

## S5. Configuration (`up4-config`)

```toml
# up4.toml
[node]
id       = "a"            # string, log label only
bind     = "10.0.0.11:7400"
fabric   = "ipv4"          # ipv4 | ipv6
pipeline = "l3fwd"         # engine name compiled into binary (S7)
threads  = 1               # rx/tx shard pairs
pin_cores = [2]            # optional; skip pinning if absent or pin fails (WARN)
ctl_socket = "/tmp/up4-a.sock"   # unix seqpacket path
metrics_interval_s = 5     # counter snapshot period; 0 disables

[[vport]]
id   = 0
peer = "10.0.0.12:7400"

[[vport]]
id   = 1
peer = "10.0.0.13:7400"

[punt]                     # optional; if absent, punt verdicts count+drop
vport = 65535              # reserved id, delivered to ctl channel (S8)
```

Validation rules (error out at startup, listing every violation, not just the
first): vport ids unique and < 65535; peers unique; bind parseable; threads in
1..=16; pipeline name exists in the compiled-in registry. `peer` tuples double
as the receive-side demux key, so two vports must not share a peer tuple.

## S6. I/O layer (`up4-io`)

### S6.1 Sockets

One UDP socket per rx/tx shard (v1: `threads = 1` → one socket bound to
`node.bind`; for `threads > 1`, N sockets with `SO_REUSEPORT` on the same
address). Construction via `socket2`: set `SO_REUSEPORT` (when threads > 1),
request `SO_RCVBUF`/`SO_SNDBUF` of 8 MiB and record the *granted* values
(kernel caps them unprivileged; log granted sizes at startup). Non-goal:
adjusting system limits.

Initialize `quinn_udp::UdpSocketState` per socket; it detects and enables
GRO/GSO where supported and degrades automatically. Log the detected
capabilities once at startup (`gro: on/off, gso: on/off, max_gso_segments`).

### S6.2 Receive path

Per shard thread, loop:

1. `recvmmsg`-style batched receive through quinn-udp into a preallocated
   arena: `RX_BATCH = 64` iovecs. Size each slot from quinn-udp itself
   (`max_udp_payload_size() * gro_segments()`); do not hardcode 64 KiB:
   `gro_segments()` is `UDP_GRO_CNT_MAX = 64` on Linux, so at up4's 1472 B
   segment a fully coalesced read is ~92 KiB and a 64 KiB slot truncates it.
   Arena is allocated once at startup.
2. For each received message: quinn-udp reports `stride` (GRO segment size).
   Iterate segments; each segment = overlay header + inner frame.
3. Demux ingress vport: lookup `(src_ip, src_port)` in a `HashMap` built from
   config at startup (read-only after start; no locking).
   Unknown tuple → count `rx_unknown_peer`, drop.
4. `up4_wire::decode`; failure → count `rx_bad_header`, drop.
5. Sequence accounting per vport: track `expected_seq`; gap → add gap size to
   `rx_seq_gap_total`; reorder (seq < expected, within window 1024) → count
   `rx_reorder`. Do not buffer or reorder; record only.
6. Invoke engine (S7) with `(frame_mut, ingress_vport)`.
7. Dispatch verdict (S6.3).

Frames longer than `INNER_MTU` after engine processing → count
`tx_oversize_drop`, drop (the engine may grow frames via encap; harness
enforces the cap).

### S6.3 Transmit path and verdict dispatch

Per shard, per-destination-vport staging queues (preallocated `Vec` of segment
descriptors into a tx arena, cleared per batch; batch-bounded capacity means it
never grows after startup). Verdicts:

- `Forward(vport)` → append to that vport's staging queue.
- `Broadcast` → append to every vport except ingress. Count `tx_broadcast`.
- `Punt` → deliver to ctl channel if `[punt]` configured (S8.3), else count
  `punt_unconfigured_drop`.
- `Drop` → count `engine_drop` (this is a *pipeline decision*, distinct from
  every harness drop counter).

Flush at end of each rx batch: for each nonempty staging queue, prepend
overlay headers (seq/ts assigned at send time) and transmit with GSO when all
segments share the (guaranteed identical) destination and size class;
otherwise plain `sendmmsg` batching. Partial sends: retry the remainder once,
then count `tx_would_block` and drop remainder (blocking sockets make this
rare; do not busy-loop).

### S6.4 Prohibitions

No io_uring in v1 (leave a `// FUTURE(io_uring)` marker in the send/recv
abstraction only). No per-packet heap allocation in either path (enforce with
a bench assertion using a counting allocator in `benches/e2e.rs`). No
cross-thread packet handoff: a frame is received, processed, and sent on the
same thread.

## S7. Engine layer (`up4-engine`)

### S7.1 Trait

```rust
pub enum Verdict { Forward(u16), Broadcast, Punt, Drop }

pub struct FrameCtx<'a> {
    pub data: &'a mut [u8],   // inner Ethernet frame, headroom guaranteed
    pub len: usize,           // current frame length
    pub headroom: usize,      // bytes available before data[0] for encap (>= 64)
    pub ingress_vport: u16,
    pub rx_ts_us: u32,        // harness receive timestamp
}

pub trait Engine: Send {
    fn process(&mut self, f: &mut FrameCtx) -> Verdict;
    fn name(&self) -> &'static str;
}
```

One engine instance per shard thread (engines may hold per-thread state;
tables are shared, S7.3). Frames are modified in place; `len` may change
within `[0, headroom + capacity]`.

### S7.2 x4c adapter

Build step: `build.rs` in `up4-engine` runs the pinned `x4c` on each program in
`p4/programs/`, emitting Rust into `src/gen/`. The adapter maps x4c's
`Pipeline` trait onto `Engine`:

- Construct SoftNPU-model ingress metadata from `FrameCtx.ingress_vport` and
  `rx_ts_us`.
- Map egress metadata: `drop=true` → `Verdict::Drop`; `broadcast=true` →
  `Verdict::Broadcast`; else `Verdict::Forward(egress.port)`; egress port ==
  punt id (65535) → `Verdict::Punt`.
- After any pipeline run that reports header modification (or
  unconditionally in v1, simplicity over cycles), zero the inner IPv4 header
  checksum field and inner L4 checksum fields if those headers are present at
  canonical offsets per the program's parser result. If the generated code
  does not expose "which headers valid," zero based on EtherType/IP-proto
  sniffing in the adapter. This is the only inner-packet touch the harness
  performs, and it implements S1.5.

**Load-time refusal:** if a program's source references queue depth/delay
intrinsic metadata or meter externs (detect by grepping the P4 source in
`build.rs` for the SoftNPU/psa identifiers), fail the build with a message
citing "no traffic manager in up4 v1." Compile-time refusal is acceptable in
place of load-time since pipelines are compiled in.

### S7.3 Table API

The ctl server (S8) manipulates tables through a typed shim generated
alongside the adapter. x4c-generated table methods take binary-serialized
keys/params with these conventions that the shim must fully encapsulate:
exact and range keys little-endian, LPM keys in wire (big-endian) byte
order, action parameters little-endian. **Upstream x4c documentation
contradicts itself here**: its Endianness section gives the key rules above,
while its control-plane walkthrough says "Numeric types are serialized in
big-endian byte order" for both key and action-parameter data. The pinned
x4c revision's generated code is the authority; the S13.1 fixed-byte-vector
tests pin whatever it actually does. Do not "fix" the shim to match a doc.
The shim exposes:

```rust
fn table_add(&self, table: &str, key: TypedKey, action: &str, params: &[TypedVal]) -> Result<()>;
fn table_remove(&self, table: &str, key: TypedKey) -> Result<()>;
fn table_dump(&self, table: &str) -> Result<Vec<EntryDesc>>;
```

Tables are shared across shard engines; wrap x4c table state in the
synchronization the generated code requires (if generated code assumes single
threaded mutation, serialize updates through a `Mutex` held only during
control operations, and document the consistency model: updates are atomic
per entry, not per batch; in-flight packets may see either version).

### S7.4 Null oracle

`NullEngine`: parses nothing, returns `Forward(1 - ingress)` for a two-port
config (config-selected static map otherwise). Feature-gated
(`--features oracle`), excluded from default builds. Used by `benches/io_only`.

### S7.5 Fallback slot

Define `mod fallback_ubpf;` containing only the `Engine` impl skeleton and a
doc comment describing the p4c-ubpf + rbpf route. Note in that comment that
p4c-ubpf emits **C** for the uBPF VM, not BPF bytecode, so the route needs a
clang → BPF-bytecode step before rbpf can load it. Do not implement in v1.

## S8. Control channel (`up4-ctl`)

### S8.1 Transport

Unix `SOCK_SEQPACKET` at `ctl_socket`. One in-process server thread. Wire
format: length-prefixed JSON (serde). No auth (filesystem permissions are the
boundary; create socket 0600).

### S8.2 Commands

`ping`, `info` (build info, pipeline name, probe results), `counters`
(snapshot, S9), `table-add`, `table-del`, `table-dump` (S7.3 shim),
`shutdown` (graceful: stop rx, flush tx, final counter snapshot, exit 0).
`up4ctl` binary is a thin clap CLI mapping 1:1 onto these with human and
`--json` output.

### S8.3 Punt delivery

If `[punt]` configured: punted frames (overlay-stripped, with ingress vport
and rx timestamp) are pushed onto a bounded SPSC queue (depth 1024) drained by
the ctl thread and exposed via a `punt-drain` command that returns up to N
frames base64-encoded. Queue full → count `punt_overflow_drop`. No packet-out
in v1 (document as v2: `packet-out <vport>`).

## S9. Metrics (`up4-metrics`)

All counters are `AtomicU64` in a flat registry, named exactly:

harness drops: `rx_unknown_peer`, `rx_bad_header`, `tx_oversize_drop`,
`tx_would_block`, `punt_unconfigured_drop`, `punt_overflow_drop`;
pipeline decisions: `engine_drop`;
traffic: per-vport `rx_pkts`, `rx_bytes`, `tx_pkts`, `tx_bytes`,
`tx_broadcast`; loss/ordering: per-vport `rx_seq_gap_total`, `rx_reorder`;
I/O shape: histogram `gro_segments_per_read` (buckets 1,2,4,8,16,32,64),
histogram `tx_batch_size` (same buckets), `syscalls_rx`, `syscalls_tx`.

Snapshot: `counters` ctl command and, if `metrics_interval_s > 0`, a JSON line
appended to `up4-metrics-<node>.jsonl`. The separation of harness-drop
counters from `engine_drop` is a product requirement: experiments must be able
to attribute every lost packet.

## S10. Conformance testing (BMv2 differential)

Per program, `p4/corpus/<name>/` holds JSON cases:
`{ "ingress_port": u16, "frame_hex": "...", "expect": { "verdict": "forward|drop|broadcast", "egress_port": u16?, "frame_hex": "..."? } }`.

- `tools/bmv2-diff/` (Python, CI container only): loads the v1model-equivalent
  program into BMv2, replays each case, records verdict + egress frame.
- Rust test `conformance.rs`: runs the same cases through the `Engine`
  directly (no sockets), compares against the BMv2-produced expectations file
  checked into the corpus dir.
- **Masking:** before diffing frames, zero these fields on both sides: IPv4
  header checksum, TCP/UDP checksums. Nothing else is masked.
- Corpus minimums per program: every parser branch taken; a truncated-header
  case per extracted header; table hit, miss, and default-action; TTL=1 and
  TTL=0 if the program decrements TTL; max-size (1460 B) and min-size (60 B)
  frames.
- CI gate: a program missing a corpus or failing a diff fails the build.

## S11. Tools

### S11.1 `probe`

Standalone binary, runs unprivileged, prints JSON: kernel release, granted
SO_RCVBUF/SO_SNDBUF for an 8 MiB request, UDP_GRO and UDP_SEGMENT setsockopt
success, quinn-udp detected capabilities, `io_uring_disabled` sysctl value if
readable, available CPUs from the cgroup mask, MTU of the route to a supplied
peer address. `up4d` runs the same probe at startup and logs it as the first
line (the "banner", one JSON object).

### S11.2 `pktgen`

Sends synthetic inner frames through a real up4 node from an unprivileged
process: configurable frame size, rate (token bucket, `--rate-pps`, 0 = max),
flow count (varies inner src/dst to defeat/exercise GRO), duration, and seq
checking on the receive side. Reports achieved pps/Gbps, loss (from seq),
and p50/p99 one-way latency using the overlay `ts_us` field (same-host runs
only for latency; cross-host latency is labeled "uncalibrated clock delta").

## S12. Error handling and logging

`tracing` with env-filter; default INFO. Startup: banner (probe JSON), config
echo, per-socket capability lines, engine name + x4c revision. Runtime: WARN
once per condition class using a rate limiter (first occurrence + count every
10 s), never per-packet logging in the fast path. All fatal startup errors
list every problem found, then exit 2. Runtime thread panic → abort the whole
process (`panic = "abort"` in release profile): a half-alive switch corrupts
experiments.

## S13. Testing matrix

1. Unit: wire encode/decode (incl. property round-trip), config validation
   (every rule), table shim endianness against fixed byte vectors, verdict
   dispatch (incl. broadcast fan-out and punt fallback).
2. Conformance: S10, per program.
3. Integration (single host, loopback, no root): two `up4d` processes with a
   two-node topology, pktgen through them; assert zero harness drops at
   10 kpps; assert table add/del changes forwarding within 100 ms without
   loss of in-flight traffic beyond the changed entries.
4. Bench (criterion, not CI-gating, results committed to `benches/RESULTS.md`
   with machine description): `io_only` (NullEngine echo), `engine_only`
   (preloaded frame ring, no sockets), `e2e`.
5. Allocation guard: counting-allocator assertion of zero fast-path allocs
   over a 1 M-frame e2e bench run.

## S14. Acceptance criteria (definition of done for v1)

A1 On two cluster nodes, default kernel settings, unprivileged: NullEngine
   path sustains ≥ 812 kpps at 1460 B inner frames (≈ 9.5 Gbps inner) single
   flow, one shard thread, 60 s, zero harness drops. If the cluster NIC lacks
   GRO/GSO, the criterion applies at 4 shard threads instead; the probe output
   is attached to the result either way.
A2 Same setup with the `l3fwd` P4 program (LPM, 1k routes): ≥ 812 kpps at
   1460 B, and a *measured and recorded* 64 B ceiling (no target; report it).
A3 All conformance corpora pass bit-identically (post-masking) against BMv2.
A4 `table add` visible in forwarding ≤ 100 ms after `up4ctl` returns.
A5 pktgen-induced overload (2× A2 rate) produces accurate loss attribution:
   `rx_seq_gap_total` + harness drop counters account for ≥ 99% of missing
   frames.
A6 Kill -TERM produces a final counter snapshot and exit 0; kill -KILL of one
   node leaves the peer running and counting `rx` silence (no crash, no spin).
A7 `cargo test` green; clippy clean (`-D warnings`); every `unsafe` site
   accounted for by the audit allowlist, each under a warrant whose structural
   rule its path satisfies (`crates/up4d/tests/unsafe_audit.rs`). This replaces
   the original "no `unsafe` outside `up4-io`" grep, which generated code and
   the VM boundary both outgrew; see [decisions.md](decisions.md) ADR-005.

## S15. Milestones (implement in this order; each ends runnable)

M1 `up4-wire` + `up4-config` + probe tool. Done when: unit tests green, probe
   runs on a stock Linux box.
M2 `up4-io` + NullEngine + pktgen. Done when: A1 achievable on loopback
   (localhost target: ≥ 812 kpps; record number).
M3 ctl channel + metrics. Done when: integration test 3 passes with
   NullEngine and counters snapshot correctly.
M4 x4c build integration + adapter + table shim, program `l2fwd` (static MAC
   table, broadcast on miss). Done when: conformance corpus for l2fwd passes.
M5 Program `l3fwd` (LPM + TTL decrement + checksum zero-fill) + punt port.
   Done when: A2, A3, A4 pass on loopback.
M6 Cluster validation + benches + RESULTS.md. Done when: A1-A7 on the real
   cluster, or deviations documented with probe output attached.
M7 Multi-host validation: all three backends forwarding between two containers
   in separate network namespaces, over a 1500-MTU veth path, `up4d`
   unprivileged, in CI. Done when: V1-V7 of [plan/m7](plan/m7-multihost.md)
   pass on every push. This is the definition of done for the three-backend
   work; it does not replace M6's throughput acceptance.
M8 Fabric transport: `DeliveryMode` as a closed sum, per-packet entropy
   spraying, selective acknowledgement, ECN/RTT sender congestion control.
   Opt-in; unreliable unordered stays the default. Done when: T1-T9 of
   [plan/m8](plan/m8-fabric-transport.md) pass. Do not start before M7.

## S16. Explicitly out of scope for v1 (do not implement)

Traffic manager/queueing/AQM; meters/counters-as-externs; clone/mirror;
recirculation; io_uring; packet-out; P4Runtime/gRPC; encryption/auth;
IPv6 inner-parsing beyond what programs do themselves; hot-swapping pipelines
at runtime (pipelines are compiled in; restart to change); Windows/macOS.

Also out of scope for v1, but *planned* rather than refused: fabric-layer
reliability, retransmission, and congestion control ([plan/m8](plan/m8-fabric-transport.md)).
v1's fabric is unreliable and unordered by design, and stays the default
afterwards — loss that the fabric repairs is loss an experiment can no longer
attribute (A5). Do not implement any of it while completing v1.

## S17. Known environmental assumptions (verify with probe, do not hardcode)

Kernel ≥ 5.x with UDP GRO/GSO available (fallback path must still work
without); cluster MTU 1500; IPv4 fabric unless config says otherwise;
`SO_REUSEPORT` available; cgroup CPU allowance ≥ configured threads. If probe
output contradicts an assumption, log WARN and continue where a fallback
exists, exit 2 where it does not (e.g., MTU < 1500 makes INNER_MTU invalid:
recompute limit from probed MTU and WARN instead of exiting).
