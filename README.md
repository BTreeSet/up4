# up4

**P4 switching in userspace. No root, no special hardware, no kernel modules.**

up4 runs compiled P4 pipelines on ordinary UDP sockets, so you can build and
test P4-based network experiments on machines where you have exactly one
privilege: running a process. Shared university clusters, CI runners, borrowed
servers. If you can run a binary and open a socket, you can run a switch.

## Why

Testing P4 programs today forces a bad choice:

- **BMv2 + Mininet**: faithful, but roughly 1 Gbps on a good day and needs
  root for namespaces and virtual interfaces.
- **DPDK / XDP targets**: fast, but they need hugepages, capabilities, NIC
  access, or an administrator who answers email.
- **Hardware**: a Tofino is not in the budget, and the cluster does not have
  one anyway.

up4 takes a fourth path. Each instance is an unprivileged process exposing
virtual switch ports. A virtual port is a UDP flow to a peer instance. Inner
packets are full Ethernet frames carried as UDP payloads behind a fixed
12 byte header. Forwarding between ports is decided by a real compiled P4
pipeline, not by hand-written harness logic. The P4 source stays the single
source of truth for what the switch does.

## What you get

- **Three ways to run the same P4.** The P4 source in `p4/programs/` is the
  artifact of record, and three independent backends execute it behind one
  `Pipeline`/`Engine` contract — pick one with `up4d --backend`. See
  [Three backends, one program](#three-backends-one-program).
- **Throughput that supports real measurements.** The I/O layer uses batched
  syscalls (`recvmmsg`) and UDP GSO/GRO through
  [quinn-udp](https://crates.io/crates/quinn-udp), the same code path that
  moves QUIC traffic in Firefox. On a 4-core development box, over loopback,
  the full path with a 1000-route `l3fwd` sustains **849 kpps / 9.9 Gbps** of
  inner traffic at 1460 B, and the datapath allocates nothing per frame.
  Numbers and machine: [benches/RESULTS.md](benches/RESULTS.md).
- **Verified behavior, not asserted behavior.** Every supported P4 program
  ships with a packet corpus whose expectations come from an independent
  model of the P4 source. CI replays it through **every backend** and diffs
  verdicts and frame bytes — egress port, header rewrites, drops — masking
  only the checksums up4 never computes. There is no exception list: a
  hand-rendering, `x4c`'s output, and `p4c`'s bytecode agree byte for byte on
  every case, or CI is red. A program without a corpus fails the build. (The
  BMv2 half of the differential is not wired yet:
  [docs/deviations.md](docs/deviations.md) D2.)
- **Honest counters.** Per-port packet, byte, and drop counters, sequence
  gap detection for overlay loss, and GRO batch histograms, so an experiment
  can always distinguish "the switch under test dropped this" from "the
  testbed dropped this."
- **Static everything.** Topology is a TOML file. No discovery protocol, no
  control channel handshake, no daemon dependencies. Start the binaries,
  send packets.

## What you do not get

We would rather state limits than let you discover them.

- **No minimum-size line rate.** 64 byte packets at 10 GbE means 14.88 Mpps.
  No socket API reaches that. up4 targets MTU-class packets and reports its
  measured small-packet ceiling instead of hiding it.
- **No traffic manager.** There is no queueing, scheduling, or AQM model.
  Programs that read queue depth or queue delay metadata are refused at
  load time rather than fed zeros that look like data.
- **No timing fidelity.** up4 preserves what your P4 program does to
  packets, not how long a Tofino would take to do it.
- **No inner checksums.** Inner IPv4/TCP/UDP checksums are zero-filled on
  rewrite and never verified. The outer UDP checksum already covers the
  whole inner frame end to end. All traffic sources and sinks are assumed
  to be testbed-controlled; do not point a real netstack at up4 and expect
  its checksums to validate.
- **No confidentiality.** The overlay is plaintext UDP on a trusted lab
  segment.

## Three backends, one program

up4 is named for uBPF's idea — the same programs, running where you have
permission. Making that true means more than one route from `.p4` to running
code, so up4 ships three and lets you choose:

| `--backend` | Where the code comes from | Allocates per frame | Cost per frame |
| --- | --- | --- | --- |
| `native` | Rust, hand-rendered from the SoftNPU source block for block | no | **30-38 ns** — the default, and what the throughput runs use |
| `x4c` | [x4c](https://github.com/oxidecomputer/p4) → Rust, committed under `crates/up4-x4c/src/generated/` | **yes** (D9) | 4.8-297 µs — a real P4 compiler emitting real Rust, at real cost |
| `ubpf` | `p4c --target ubpf` → BPF bytecode, run in-process on [rbpf](https://crates.io/crates/rbpf) | no | 1.1-2.9 µs interpreted — full P4 expressiveness; JIT-compiled on x86-64 (D11) |

Measured on aarch64 at 64 B, so the `ubpf` figures are the interpreter; the
JIT is the default on x86-64 and has not been measured yet. `x4c`'s upper
figure is `l3fwd` with a thousand routes, where its LPM table is searched
linearly — about 290 ns per installed route. Pick `x4c` when what matters is
that a P4 compiler produced the Rust, not when throughput does.
[benches/RESULTS.md](benches/RESULTS.md) has the full table and the machine.

They are interchangeable, not merely coexisting: `up4_catalog::build` is total
over `Program × Backend`, every backend of a program exposes the same tables to
`up4ctl`, and the conformance corpus holds all three to the same verdicts and
the same output bytes. The `.p4` is the artifact of record for all of them.

What up4 refuses to claim: `native` is a *hand* rendering, so only the corpus
ties it to the source — nothing mechanical does. `x4c` cannot compile
`transition select`, which is why `l3fwd`'s ethertype demux sits in `apply` in
the SoftNPU binding and in the parser in the uBPF one. Each backend reports
what it actually is — provenance, allocation profile, execution mode — through
`up4ctl info`, and the documentation quotes that rather than making claims of
its own.

## How it works

```
 node A (unprivileged process)            node B (unprivileged process)
+---------------------------+            +---------------------------+
|  P4 pipeline (backend of  |            |  P4 pipeline (backend of  |
|  native / x4c / ubpf)     |            |  native / x4c / ubpf)     |
|      vport 0   vport 1    |            |      vport 0   vport 1    |
+--------|----------|-------+            +-------|----------|--------+
         |          |    UDP + 12B header        |          |
         |          +--------------------------->+          |
         +------------------------------------------------->+
                     cluster network, 1500 MTU
```

Overhead budget: 20 bytes outer IPv4 + 8 bytes UDP + 12 bytes up4 header =
40 bytes, leaving a 1460 byte inner MTU on a standard 1500 byte network.
The up4 header carries a version, the sender's ingress port, a sequence
number for loss accounting, and a coarse timestamp. Topology is out of band:
receivers map source address to ingress port from the static config.

```toml
# up4.toml
[node]
id       = "a"
bind     = "10.0.0.11:7400"
pipeline = "l3fwd"           # the P4 program; the backend that runs it
                             # is `up4d --backend`, defaulting to native

[[vport]]
id   = 0
peer = "10.0.0.12:7400"   # node b, vport 0

[[vport]]
id   = 1
peer = "10.0.0.13:7400"   # node c, vport 0
```

## Quick start

```sh
cargo build --release
./scripts/demo.sh          # two routers and a generator on loopback, no sudo
```

`demo.sh` is the shortest path to a running switch: it writes two topologies,
starts two `up4d` processes, installs routes, pushes traffic through both, and
prints the counters. What it does by hand:

```sh
# what this host will let up4 do — buffers, GRO/GSO, cgroup CPUs, route MTU
./probe --peer 10.0.0.12 --pretty

# start a node; --tables installs routes before the datapath comes up
./up4d --config up4.toml --tables routes.json

# the same program, compiled by p4c instead of rendered by hand
./up4d --config up4.toml --tables routes.json --backend ubpf

# what is loaded, and what its tables will accept
./up4ctl --socket /tmp/up4-a.sock info
./up4ctl --socket /tmp/up4-a.sock tables
# table ipv4_lpm
#   key    ipv4.dst : lpm   (ipv4 (10.0.0.1)/prefix_len)
#   action forward(port: u16 (e.g. 1 or 0x1f), dmac: mac (aa:bb:cc:dd:ee:ff))
#   action punt()
#   action drop()

# add a route, positionally or by name; both mean the same thing
./up4ctl table add ipv4_lpm 10.0.2.0/24 forward port=1 dmac=02:00:00:00:00:02
./up4ctl table dump ipv4_lpm
./up4ctl table load routes-1k.json      # a batch, for the 1000-route runs

# offered load, and what actually came back
./pktgen --bind 10.0.0.9:7500 --target 10.0.0.11:7400 \
         --frame-size 1460 --rate-pps 800000 --duration 60

# every counter, and a clean stop
./up4ctl counters --json | jq .harness_drops
./up4ctl shutdown
```

## Design principles

1. **P4 is the artifact of record.** No forwarding decision lives in harness
   code. A native Rust null pipeline exists as a performance oracle for
   benchmarks and is compiled out of experiment builds.
2. **Unprivileged means unprivileged.** No capabilities, no sysctls, no
   ethtool, no hugepages, anywhere, ever. Features the kernel does not
   offer (GSO/GRO on odd NICs, io_uring on hardened hosts) are probed at
   startup and reported, and the plain batched-syscall path must still meet
   the throughput target.
3. **Fail loudly.** Oversized frames, unknown peers, refused pipelines, and
   engaged fallbacks are counted and logged. A testbed that drops packets
   silently is worse than a slow one.
4. **Measure before optimizing.** I/O-only, engine-only, and end-to-end
   benchmarks are maintained from day one, and no fast-path change lands
   without a benchmark delta.

## Status and roadmap

Working, tested on loopback, and green in CI:

- [x] Cluster probe: kernel, GRO/GSO, granted socket buffers, cgroup CPUs, MTU
- [x] I/O core: batched receive, GRO segment walk, GSO transmit, zero
      per-frame allocation
- [x] `Engine`/`Pipeline` contracts, the match-action core, and two programs
      (`l2fwd`, `l3fwd`) on all three backends
- [x] `cargo xtask` toolchain: provisions x4c and p4c into a self-contained
      userspace prefix, regenerates every artifact, and reconciles drift
- [x] Control channel: typed table shim, schema discovery, batch load, punt
      drain, counter snapshots, graceful shutdown
- [x] Differential conformance corpora, gated in CI
- [x] Broadcast replication and punt port
- [x] Two routers and two generators forwarding both ways, unprivileged, with
      every lost frame attributable

Outstanding:

- [ ] The BMv2 half of the differential ([deviations D2](docs/deviations.md))
- [ ] Measure the uBPF JIT on an x86-64 host — it is the default there and the
      corpus covers it, but no number has been taken
      ([deviations D11](docs/deviations.md))
- [ ] Cluster validation A1–A7 on real NICs ([m6](docs/plan/m6-cluster-benches.md))
- [ ] *Post-v1 (out of scope for v1, spec S16):* optional per-port token
      bucket shaper, only if experiments need congestion signals to mean
      something

## Name

eBPF became uBPF when the VM left the kernel. up4 is P4 with the same idea:
same programs, same semantics, running where you actually have permission.

The three backends are what makes that more than a slogan. "Userspace P4" is
not one technique, so up4 does not pretend it is: a hand-rendering you can read,
a P4-to-Rust compiler, and P4-to-bytecode in a VM are three real answers with
three different trade-offs, and up4's job is to let you take whichever one your
experiment needs without changing the `.p4` or the harness around it.
