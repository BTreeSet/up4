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

- **A real P4 toolchain.** Pipelines are compiled from P4 source by
  [x4c](https://github.com/oxidecomputer/p4) into native Rust code
  implementing a `Pipeline` trait. A p4c-ubpf backend behind the same engine
  trait is planned as a fallback for programs that need constructs x4c does
  not cover yet.
- **Throughput that supports real measurements.** The I/O layer uses batched
  syscalls (`sendmmsg`, `recvmmsg`) and UDP GSO/GRO through
  [quinn-udp](https://crates.io/crates/quinn-udp), the same code path that
  moves QUIC traffic in Firefox. Design target: 10 GbE line rate at MTU-size
  packets on a single core, with default kernel settings. The same technique
  carries WireGuard's userspace implementation past 10 Gbit/s.
- **Verified behavior, not asserted behavior.** Every supported P4 program
  ships with a packet corpus. CI runs the corpus through BMv2 and through
  up4 and diffs the verdicts: egress port, header rewrites, drops. A program
  without a corpus is not supported.
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

## How it works

```
 node A (unprivileged process)            node B (unprivileged process)
+---------------------------+            +---------------------------+
| P4 pipeline (x4c -> Rust) |            | P4 pipeline (x4c -> Rust) |
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
# topology.toml
[node]
id   = "a"
bind = "10.0.0.11:7400"

[[vport]]
id   = 0
peer = "10.0.0.12:7400"   # node b, vport 0

[[vport]]
id   = 1
peer = "10.0.0.13:7400"   # node c, vport 0
```

## Quick start

> Status: design stage. The commands below describe the intended v1
> interface and will change.

```sh
# compile a P4 program to a pipeline
x4c switch.p4 -o pipeline.rs

# build up4 with the pipeline
cargo build --release

# on each node, no sudo anywhere
./up4 --config topology.toml --pipeline switch

# add a table entry through the local side channel
./up4ctl table add ingress.fwd.fib --key 02:00:00:00:00:01 --action forward --port 1
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

- [ ] Gate test: compile the lab's target P4 programs with x4c
- [ ] Cluster probe: kernel version, GRO/GSO support, socket buffer caps
- [ ] I/O core: batched UDP echo path at target rate
- [ ] Engine integration behind the `Engine` trait
- [ ] BMv2 differential conformance CI
- [ ] Broadcast replication and punt port
- [ ] Optional per-port token bucket shaper (only if experiments need
      congestion signals to mean something)

## Name

eBPF became uBPF when the VM left the kernel. up4 is P4 with the same idea:
same programs, same semantics, running where you actually have permission.
