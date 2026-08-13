# Decision record

Why up4 is shaped the way it is. One entry per decision that a reader could
otherwise mistake for an accident, newest last.

This file answers "why", [spec.md](spec.md) answers "what", and
[deviations.md](deviations.md) answers "where the two disagree". A decision
that *departs* from the spec gets an entry in both: here for the reasoning,
there for the departure. Entries are append-only; a superseded decision is
marked so and left in place, because the reasoning is the record.

Each entry carries an **Enforced by** line naming the test, audit, or CI job
that fails when the decision is violated. A decision with no enforcement is a
preference, and is labelled as one.

---

## ADR-001 — Three backends, one `Engine`/`Pipeline` contract

**Context.** "Userspace P4" is not one technique. A hand-written rendering, a
P4-to-Rust compiler, and P4-to-bytecode in a VM are three different answers,
with different provenance, expressiveness, and cost.

**Decision.** Ship all three behind one contract, selected at configuration
time by `up4d --backend`. `up4_catalog::build` is total over
`Program × Backend`; there is no name-lookup registry that can fail at runtime.

**Consequences.** An unknown pipeline is rejected at `Selection::parse`, during
configuration, with the alternatives listed. Adding a program means adding a
variant and letting exhaustive `match` find every site. Every backend of a
program exposes the same tables, so `up4ctl` cannot tell them apart.

**Enforced by** `up4-catalog`'s `every_selection_builds_and_names_itself` and
`every_backend_of_a_program_exposes_the_same_tables`.

---

## ADR-002 — The `.p4` is the artifact of record; generated output is committed

**Context.** Two compilers produce two of the three backends. `x4c` and `p4c`
are large native builds — p4c needs bison, flex, boost, and a C++ toolchain.
A `build.rs` that shells out to them makes every `cargo build`, on every
machine, depend on provisioning them.

**Decision.** Generation is a `cargo xtask` target and its output is checked
in. The normal build needs nothing but `cargo`.

**Consequences.** The failure mode becomes "a `.p4` was edited without
regenerating", which is cheap to detect and does not need a compiler:
`cargo xtask audit` hashes each source against `p4/generated.lock` in about
100 ms and runs on every CI job. The expensive check — rebuild both compilers
in a self-contained userspace prefix and diff the bytes — is `cargo xtask
verify`, on a schedule, with the time it needs.

**Enforced by** the `p4` CI job (`cargo xtask audit`) and the weekly
`p4-artifacts` workflow (`cargo xtask verify`). See
[deviations.md](deviations.md) D1.

---

## ADR-003 — What up4 adds around a program belongs to the *program*, not to a backend

**Context.** Twice, a behaviour that up4 wanted lived in exactly one backend.
The `native` parser refused IPv4 headers that contradict themselves — a check
no `.p4` performs — so it dropped frames the compiled backends forwarded. And
`zero_inner_checksums` sat inside `native`'s `l3fwd`, so only `native`
zero-filled the transport checksum. The conformance corpus *masks* that field,
so it never saw the disagreement.

Three renderings of one program that refuse different frames, or emit different
bytes, are three programs. Agreeing only on the frames they all forward is too
weak a claim to hang "interchangeable" on.

**Decision.** Model the envelope explicitly:

```
up4(program) = admit(program) ; p4(program) ; scrub(program)
```

`Admission` and `Scrub` are closed sums declared by `Program::envelope()`.
`up4_catalog::build` composes them onto the compiled backends. `native` is left
unwrapped because it already computes both ends inline — fusion, not omission.

**Consequences.** The conformance corpus has **no exception list**: all three
backends agree on every case, including the malformed ones. Neither check can
be written in a `.p4` — a P4 parser rejects when `extract` runs out of bytes
and for no other reason, and the transport checksum is bytes no deparser emits
— so this is where they belong.

**Enforced by** `admission_binds_every_backend_of_a_program` (all 256 values of
the IPv4 version/IHL byte, against all three backends),
`fusion_is_sound_for_every_version_and_ihl` (proves `native`'s fusion is exact,
which is what licenses leaving it unwrapped), and the e2e crossing check, which
asserts the zero-fill for every backend — the proof the corpus mask cannot give.
See [deviations.md](deviations.md) D10.

---

## ADR-004 — The uBPF backend JIT-compiles on x86-64, and gives up rbpf's memory checking

**Context.** `register_allowed_memory` bounds every load and store the rbpf
*interpreter* makes into the VM's buffers, and the VM boundary's `unsafe` is
justified partly by it. rbpf's JIT ignores it and performs no runtime memory
checking at all.

**Decision.** JIT wherever the target architecture has one; the variant does
not exist anywhere else. up4's testbed is x86-64, and the measured alternative
is an interpreter costing microseconds per frame.

**Consequences.** Under `ExecMode::Jit` the only thing keeping generated code
inside its buffers is the bounds checking p4c already emits against
`packet_length`, which up4 supplies. That is in-kernel eBPF's bargain — a
static argument in place of a dynamic check — taken deliberately rather than
inherited from a default.

**Enforced by** the conformance corpus running through **every** `ExecMode` the
target has, not just the default (`runners()` in
`crates/up4-catalog/tests/conformance.rs`) — "the interpreter agrees" is not
evidence about the JIT. Plus `every_shipped_program_compiles_in_every_mode`,
because rbpf emits into a single 4 KiB page and overflowing it panics, fatally
under `panic = "abort"`. See [deviations.md](deviations.md) D11.

---

## ADR-005 — `unsafe` is allowlisted by structural warrant, not by directory

**Context.** Spec S1.7 confined `unsafe` to `up4-io`'s syscall plumbing and A7
enforced it with a grep. Then generated code arrived carrying
`unsafe impl Send`, and a VM boundary arrived needing to read a lookup key out
of memory the VM owns. The grep was correct and the rule was too narrow.

**Decision.** A closed `Warrant` enum — `SyscallPlumbing`, `Generated`,
`VmBoundary`, `BenchHarness` — where each variant carries a *structural rule*
its file's path must satisfy. `Generated` code must actually live under a
`src/generated/` directory; `SyscallPlumbing` must actually be in the crate
that owns syscalls. Site counts are exact.

**Consequences.** The label and the fact are checked against each other, so a
hand-written file cannot be waved through as generated. `unsafe` growing inside
an already-allowed file is as visible as a new file.

**Enforced by** `crates/up4d/tests/unsafe_audit.rs`. Supersedes the A7 grep in
spec S14 and in `docs/plan/m6-cluster-benches.md`.

---

## ADR-006 — A CI cache key must be exactly a declared profile name

**Context.** `shared-key` *replaces* the job key in `Swatinem/rust-cache`, so
two jobs sharing a key share an entry. A key naming something that is not a
build profile can name an entry that holds nothing, or worse, an entry filled
by a job building something else.

**Decision.** Every `shared-key` must be the exact name of a declared Cargo
profile. New profiles may be declared as needed (for instance one for
architectures with a JIT and one without); the key must still match the profile
name exactly, so a cache entry that cannot hold what its name claims is
unrepresentable.

**Enforced by** `crates/up4d/tests/ci_cache_keys.rs`, which scans every
workflow and checks three invariants: every key is a declared profile, a keyed
job builds exactly that profile, and a job that builds nothing claims no entry.

---

## ADR-007 — Multi-host validation uses containers, not `sudo ip netns`

**Context.** The definition of done requires up4 running across more than one
machine, with real traffic. Loopback cannot show that: `lo` has MTU 65536 and
no driver, so the measured path omits segmentation, a netdev transmit path, and
a second network stack entirely.

Spec S1.1 forbids up4 requiring network namespaces. That is a constraint on the
**system under test**, not on the harness that builds the topology — but the
two are easy to confuse, and confusing them would silently retire the
unprivileged claim.

**Decision.** Two Docker containers on a user-defined bridge network, each with
its own network namespace, MTU 1500, joined by veth. `up4d` runs inside as a
**non-root user**.

Rejected: `sudo ip netns add` plus a hand-built veth pair. It needs root on the
runner for every step, GitHub's passwordless `sudo` has regressed before
([actions/runner-images#9303](https://github.com/actions/runner-images/issues/9303)),
and it puts privileged commands next to the thing whose whole claim is that it
needs none. Docker is preinstalled on GitHub-hosted Ubuntu runners and gives
each container a namespace without any of that.

**Consequences.** The privilege boundary becomes checkable: the harness may
create namespaces, the binaries may not, and the process under test must prove
it is not root rather than merely be believed. A container that ran `up4d` as
root would pass every functional assertion while invalidating the one claim up4
exists to make.

**Enforced by** the `Audit privileged interfaces` CI job (extended to cover
`scripts/`, with the harness script named as the single warranted exception),
and by M7's own `euid != 0` assertion. See
[plan/m7-multihost.md](plan/m7-multihost.md).

---

## ADR-008 — The fabric transport is a fabric-layer concern, never a P4 program

**Context.** up4 should align with modern AI/ML fabric transports (MRC, Ultra
Ethernet). A natural-looking but wrong reading is to express them as P4.

**Decision.** Transport work lives in `up4-wire` and `up4-io`. No part of it is
ever written in a `.p4`, compiled by x4c or p4c, or executed by a backend.

**Consequences.** This is not a limitation, it is the layering. The transport
carries inner Ethernet frames between up4 nodes; the P4 program decides what to
do with a frame once it has arrived. They are on opposite sides of the
`Engine` contract. Writing multipath spraying or selective retransmission in
P4 would also be infeasible in practice — neither belongs in a match-action
pipeline, and x4c's expressible subset excludes the control flow either would
need.

The payoff is that all three backends get the transport for free and none of
them can perturb it, which is the same argument as ADR-003 pointing the other
way: what is common to every backend belongs outside all of them.

**Enforced by** the layering itself — `up4-wire` and `up4-io` do not depend on
`up4-engine`. See [plan/m8-fabric-transport.md](plan/m8-fabric-transport.md).

---

## ADR-009 — Delivery mode is a closed sum, and unreliable stays the default

**Context.** Ultra Ethernet defines four packet delivery modes: RUD, ROD, RUDI,
and UUD (UE Specification v1.0.3, §3.5.6, p. 232). MRC extends RoCEv2 with
per-packet multipath and selective retransmission. Both are reliable
transports, and adding reliability to up4's fabric is the obvious way to
"align with industry practice".

It is also the obvious way to break up4's most valuable property. up4 is a
testbed. Its counters exist so an experimenter can tell "the switch under test
dropped this" from "the testbed dropped this" (spec A5). A fabric that
retransmits silently repairs the second case and destroys the measurement.

**Decision.** Model delivery mode as a closed sum mirroring UE's four names,
implement the ones up4 can honestly implement, and keep **unreliable unordered
the default**. Reliability is opt-in, per node, and reported by `up4ctl info`.

**Consequences.** up4's current fabric is not "missing a transport" — it *is*
UUD, and naming it so makes the alignment claim precise instead of aspirational.
An experiment that wants loss attribution keeps it. An experiment that wants to
study a reliable multipath transport selects one and knows it did.

This departs from spec S1.4 ("no negotiation, no in-band control messages"),
which reliable modes require. That departure is scoped to the modes that need
it: UUD continues to negotiate nothing, so the default configuration still
satisfies S1.4 exactly as written.

**Enforced by** M8's mode-conformance tests: every delivery mode is held to its
own stated guarantee under injected loss and reorder, and UUD is asserted to
send no control traffic whatsoever.

---

## Sources

Checked 2026-08-12. Both are primary sources; neither is quoted beyond fair
use, and neither is vendored — the Ultra Ethernet specification is published
under CC BY-ND 4.0, which permits redistribution of the document but **not**
distribution of derivative works, so up4 cites it and does not copy it.

- **Ultra Ethernet Specification v1.0.3**, Ultra Ethernet Consortium,
  dated July 16, 2026 (PDF metadata: created 2026-08-05).
  <https://ultraethernet.org/wp-content/uploads/sites/20/2026/08/UE-Specification-1.0.3.pdf>
  Transport layer is §3, structured as four sublayers: Semantic (SES),
  Packet Delivery (PDS), Congestion Management (CMS), and Transport Security
  (TSS) (§3.2.1-3.2.4). Delivery modes are §3.5.6-3.5.7. Congestion control
  algorithms are §3.6, including network signal-based congestion control
  (§3.6.13) and receiver-credit congestion control (§3.6.14).
- **The Multipath Reliable Connection (MRC) Transport**, Sohan, Spada, Davis,
  Handley, Burstein et al., arXiv:2606.18170v1, June 16, 2026.
  <https://arxiv.org/html/2606.18170v1>
  Extends RoCEv2 with per-packet multipath via an Entropy Value field,
  sender-based congestion control (NSCC) driven by ECN and RTT-derived queueing
  delay, SACK/NACK with a cumulative acknowledgment plus an out-of-order
  bitmask, switch-trimmed packets, reliability probes, and a Maximum PSN Range
  window bounding packets in flight.
