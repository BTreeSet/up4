# M8: an MRC/UE-aligned fabric transport, opt-in

Spec: S4 (wire), S6 (I/O), S1.4 (static topology), S16 (out of scope for v1).
Decisions: [ADR-008](../decisions.md#adr-008--the-fabric-transport-is-a-fabric-layer-concern-never-a-p4-program),
[ADR-009](../decisions.md#adr-009--delivery-mode-is-a-closed-sum-and-unreliable-stays-the-default).

**Done when:** `DeliveryMode` is a closed sum, each implemented mode is held to
its own stated guarantee under injected loss and reorder, `Uud` remains the
default and provably sends no control traffic, and `up4ctl info` reports the
mode in force.

Do not start M8 before [M7](m7-multihost.md) is done. A transport whose only
evidence comes from loopback has no evidence: reordering, path diversity, and
queueing are precisely what `lo` does not have.

---

## What this is aligned with, and how closely

Two current designs, checked 2026-08-12 (citations in
[decisions.md](../decisions.md#sources)):

| Idea | MRC | Ultra Ethernet v1.0.3 | up4 can |
|---|---|---|---|
| Per-packet multipath | Entropy Value varied per packet | entropy per packet | **yes** — vary the UDP source port; ECMP hashes the 5-tuple |
| Reliable unordered, out-of-order placement | core mode | RUD (§3.5.7.1) | **yes** |
| Reliable ordered, single path | — | ROD, GoBackN, single entropy (§3.5.7.2) | **yes** |
| Unreliable unordered | — | UUD (§3.5.7.4) | **yes — already shipped** |
| Selective ack: cumulative ack + out-of-order bitmap | SACK/NACK | PDS ACK/NACK | **yes** |
| Bounded packets in flight | Maximum PSN Range | PDS windowing | **yes** |
| Sender CC from ECN + RTT | NSCC | network signal-based CC (§3.6.13) | **yes** — quinn-udp already carries ECN both ways |
| Receiver-credit CC | host backpressure | receiver-credit CC (§3.6.14) | later; needs a credit channel |
| Switch-trimmed packets | yes | — | **no** — requires switch support up4 does not have |
| Direct data placement / RDMA verbs | yes | SES (§3.4) | **no** — up4 forwards frames; there is no memory semantic |
| Source routing (SRv6 uSID, structured EV) | yes | — | **no** — needs fabric cooperation |
| Transport security sublayer | — | TSS (§3.7) | **no** — spec S16 excludes encryption |

The honest claim this milestone earns is therefore narrow and worth stating
exactly: **up4 implements UE-shaped delivery modes with per-packet entropy
spraying and ECN/RTT sender congestion control, in unprivileged userspace over
UDP.** It is not a UE implementation, does not interoperate with one, and will
never approach production speeds. Say that in the README rather than letting
"UEC-aligned" travel unqualified.

RUDI (§3.5.7.3) is deliberately absent from the model below. It exists to
exploit idempotent memory operations; up4 forwards Ethernet frames and has no
idempotency notion to exploit, so a RUDI variant would be a name with nothing
behind it.

---

## 1. Domain model

```rust
/// How the fabric delivers overlay packets between two up4 nodes.
///
/// Mirrors Ultra Ethernet's packet delivery modes (UE v1.0.3 §3.5.6), minus
/// RUDI, which has no meaning for a frame forwarder. Closed: a mode up4 does
/// not implement is not a variant, so there is no unimplemented arm to reach.
pub enum DeliveryMode {
    /// Unreliable, unordered. No control traffic, no state, no retransmission.
    /// The default, and what up4 has always done (UE calls this UUD).
    Uud,
    /// Reliable, unordered: every packet delivered once, in arrival order.
    /// Sprays across paths; recovers with selective retransmission.
    Rud,
    /// Reliable, ordered: every packet delivered once, in send order.
    /// Single entropy, GoBackN recovery.
    Rod,
}

/// A fabric path selector. One value = one 5-tuple = one ECMP path.
///
/// Invariant: `Entropy` is only ever *varied* by the sender. The receiver never
/// interprets it, which is what keeps path choice from becoming protocol.
struct Entropy(u16);          // becomes the UDP source port

/// Packets in flight, bounded. UE bounds this in PDS; MRC calls it the
/// Maximum PSN Range. Bounded is the invariant: an unbounded retransmit buffer
/// is a memory leak with a protocol wrapped around it.
struct Window { size: NonZeroU32 }

/// One peer's delivery state. Absent for `Uud` — not empty, absent.
enum PeerState {
    Stateless,                          // Uud
    Reliable(Box<ReliablePeer>),        // Rud | Rod
}
```

The `PeerState` sum is the shape that matters. A `ReliablePeer` allocated but
unused for `Uud` would be a per-peer megabyte that no invariant forbids, and a
`Option<ReliablePeer>` invites `unwrap()`. Absence is a variant.

### The wire consequence nobody expects

Spec S4 says the receiver derives ingress vport from the **source tuple**, and
that the header's `ingress_vport` field is "tracing only".

Per-packet entropy varies the UDP source port. **Those two facts are
incompatible.** Spraying across paths changes the source tuple every packet, so
a receiver deriving ingress from it would attribute one flow to many vports.

Resolution, and it must be explicit rather than emergent:

- Flag bit 0 of `ver_flags` (S4 reserves the low nibble, all 0 in v1) means
  *`ingress_vport` is authoritative*.
- A sender that sprays MUST set it. A receiver that sees it MUST take ingress
  from the header and MUST NOT consult the source port.
- A receiver that does not understand the flag rejects the packet — it is a
  version mismatch in all but name, and silently misattributing traffic is
  worse than dropping it.

This is a change to what a byte *means*, not just to what is in it, which is
why it gets a flag bit and a conformance case rather than a comment.

---

## 2. Pure core

Every function total, no I/O, no clock — the clock is an argument.

```rust
// Sender
fn on_send(s: SendState, pkt: Psn, now: Micros) -> (SendState, Vec<Emit>)
fn on_ack (s: SendState, ack: Sack,  now: Micros) -> (SendState, Vec<Emit>)
fn on_tick(s: SendState,             now: Micros) -> (SendState, Vec<Emit>)   // RTO

// Receiver
fn on_recv(r: RecvState, pkt: Psn) -> (RecvState, Deliver, Option<Sack>)

// Congestion control, separable and testable on its own
fn on_signal(c: Cwnd, ecn: EcnCe, rtt: Micros) -> Cwnd
```

`Deliver` is a sum, not a bool: `Now`, `Duplicate` (drop, count it), or
`Buffered` (ROD only). Boolean blindness here is how duplicate suppression
turns into silent frame loss.

`on_tick` taking `now` rather than reading a clock is what makes loss recovery
testable without sleeping. Every timing test in this milestone must drive
`now` explicitly; a test that sleeps is a test that flakes.

---

## 3. Effect boundary

| Effect | Where | Notes |
|---|---|---|
| Send / receive | `up4-io` shard loop | already exists; adds control packets |
| Retransmission timer | the shard's existing `poll` timeout | **no timer thread.** S1.2 forbids an async runtime, and a second thread per peer would be worse. The shard already waits on readiness with a bounded timeout; `on_tick` runs on that heartbeat |
| Clock | one `CLOCK_MONOTONIC` read per loop iteration, passed down | not per packet |
| Entropy selection | sender, round-robin over K ports | never negotiated, never signalled |
| Retransmit | idempotent by PSN | a duplicate is detected and counted, never delivered twice |
| Connection setup | **none** | up4's topology is static (S1.4). Peers are configured, not discovered. There is no handshake to get wrong |

That last row is where up4 diverges from both references and comes out ahead
for its purpose: MRC sets up QPs out of band and UE establishes PDCs
dynamically, because both serve dynamic workloads. up4's peers are in a TOML
file read once. Reliability needs sequence state, not a connection.

---

## 4. Complexity budget

Sizes: `W` = window in packets (default 1024), `K` = distinct entropies
(default 16), `P` = peers (single digits), MTU 1500.

| Operation | Frequency | Bound | Structure |
|---|---|---|---|
| Send one packet | per frame | O(1) | ring of `W` descriptors indexed by `psn % W` |
| Record arrival | per frame | O(1) | `W`-bit arrival bitmap, one word per 64 PSNs |
| Build a SACK | per ack | O(W/64) words | cumulative ack + fixed 64-bit out-of-order mask |
| Apply a SACK | per ack | O(bits set), amortized O(1) per packet | advance the ring's tail |
| Choose an entropy | per frame | O(1) | round-robin index, no hashing |
| RTO scan | per loop iteration, not per packet | O(1) | earliest-deadline head of the ring |
| Retransmit buffer | — | **O(W × MTU) per reliable peer** = 1.5 MB at defaults | preallocated at startup |

State the memory. A reliable peer costs 1.5 MB of retransmit buffer at the
default window; eight peers is 12 MB, allocated once at startup and never on
the fast path. If that is too much for a target, the window is the knob, and
shrinking it costs throughput on long paths — say so in the config comment
rather than making it a surprise.

The RTO scan is the one to get right. A naive design scans all `W` descriptors
per tick; at `W` = 1024 and a millisecond heartbeat that is a million
comparisons a second doing nothing. The ring is filled in PSN order, so the
oldest unacknowledged packet is at the tail — check the tail, stop.

---

## 5. Rejected alternative

**Implement UE's transport faithfully: SES, PDS, CMS, and TSS.**

Killed by four independent constraints, any one of which is sufficient:

1. SES is a *memory* semantic — RMA reads and writes with direct data placement
   into host memory. up4 moves Ethernet frames. There is nothing for SES to
   describe.
2. Trimming requires switches that truncate dropped packets and forward the
   headers at high priority. up4 runs on borrowed clusters where it does not
   control a single switch.
3. TSS is encryption, which spec S16 excludes from v1.
4. It would not interoperate anyway. Partial UE over UDP that cannot talk to a
   UE endpoint has all the cost of the standard and none of the benefit.

Taking the *mechanisms* both designs converged on — per-packet entropy,
selective ack, bounded flight, ECN/RTT sender control — is the part that
transfers to a UDP overlay. Taking the *layering* is not.

---

## 6. Validation standard

Each mode is tested against its own guarantee, under a fault injector that
drops and reorders deterministically from a seed. Determinism is not optional:
a transport test that depends on real loss is a test that fails on Tuesdays.

| # | Property | Mode | Method |
|---|---|---|---|
| T1 | No control traffic at all; byte-identical to today's behaviour | `Uud` | packet count on the wire equals frames offered, exactly |
| T2 | Every frame delivered exactly once under 10% loss | `Rud`, `Rod` | seeded drop injector; assert delivered set equals offered set |
| T3 | Delivery order equals send order | `Rod` | seeded reorder injector |
| T4 | Delivery order may differ; no duplicates, no loss | `Rud` | same injector, weaker assertion — assert it *does* reorder, else the test is vacuous |
| T5 | Packets in flight never exceed `W` | `Rud`, `Rod` | instrument the sender; property test over seeds |
| T6 | Duplicates counted, never delivered twice | `Rud`, `Rod` | inject duplicates explicitly |
| T7 | Loss attribution still works | `Uud` | S14 A5 unchanged — this is what ADR-009 protects |
| T8 | Sprayed traffic attributes ingress correctly | `Rud` | multi-entropy send; assert vport attribution from the header flag |
| T9 | No allocation on the fast path | all | the existing counting-allocator guard, extended to reliable modes |

T4's second clause matters. "No duplicates, no loss" passes trivially if the
injector never actually reorders anything. Assert that the arrival order
differed from the send order in at least one seed, or the property is untested.

---

## 7. Open questions, with the default assumed if nobody answers

1. **Window default.** 1024 packets (1.5 MB/peer). Assumed until a
   bandwidth-delay product from the real cluster says otherwise; on a
   sub-millisecond fabric it is far more than needed.
2. **Does `Rod` earn its place?** It is single-path GoBackN, i.e. strictly
   worse than `Rud` for a frame forwarder that does not need ordering.
   Default: implement `Uud` and `Rud` first, and add `Rod` only if an
   experiment asks for it — a variant with no user is a variant with no tests.
3. **ECN on a borrowed cluster.** Marking requires switch configuration up4
   does not control. Default: read ECN if present, fall back to RTT-only
   congestion control, and report which signal is in use via `up4ctl info`
   rather than silently degrading.

## Verify

```sh
cargo test -p up4-io transport::          # T1-T9, all seeded, none sleeping
cargo test -p up4-wire                    # header flag semantics, round-trip
./scripts/multihost.sh --mode rud         # M7's topology, reliable mode
```
