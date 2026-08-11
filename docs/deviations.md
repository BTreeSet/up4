# Deviations from the spec

The spec (`docs/spec.md`) is the artifact of record. Where this implementation
departs from it, the departure is listed here with its reason. Nothing in this
file overrides the spec; it records where reality and the document disagree and
what was done about it.

## D1 — Pipelines are hand-rendered from the P4 source, not x4c-generated

**Spec:** S7.2 — `build.rs` runs a pinned `x4c` over `p4/programs/*.p4` and the
adapter maps the generated `Pipeline` onto `Engine`.

**Here:** `p4/programs/l2fwd/l2fwd.p4` and `l3fwd.p4` are the artifacts of
record (spec P1), and `crates/up4-engine/src/programs/{l2fwd,l3fwd}.rs` are
direct renderings of them — parser, ingress control, table application and
deparse-time fix-ups, block for block, with the correspondence written into
each module's doc comment. The two contracts x4c-generated code would plug
into (`Engine`, `Pipeline`) are exactly the ones the renderings implement.

**Why:** the MVP's job is to show that P4 semantics over UDP forwards packets
unprivileged at line rate. Adding a large external compiler to the build — one
whose generated-code ABI is not pinned here and whose availability in CI is not
guaranteed — buys nothing toward that and risks the whole thing.

**What keeps this a seam rather than a fork:**

- `crates/up4-engine/src/x4c.rs` holds the adapter's contract: the byte-level
  key and parameter ABI with the fixed-vector tests spec S13.1 asks for, the
  egress-metadata-to-verdict mapping, and the record of the upstream
  endianness contradiction.
- `x4c::refuse_reason` implements S7.2's compile-time refusal (queue-depth and
  meter intrinsics) and is applied to the checked-in `.p4` sources by a test,
  ready to be called from `build.rs`.
- The conformance corpora (S10) diff the *renderings* against an independent
  model of the P4 source, so a rendering that drifts from its program fails.

**To close it:** add the `build.rs` step, emit into `src/gen/`, implement the
adapter against `x4c.rs`'s ABI, and delete the rendering modules. The corpora,
the registry, the shim, and every test above them stay as they are.

## D2 — The BMv2 differential runner is not wired

**Spec:** S10 — `tools/bmv2-diff/` replays each corpus through BMv2 in a CI
container and writes the expectations file.

**Here:** `tools/corpus/gen_corpus.py` produces the expectations from an
independent model of the P4 source, and `conformance.rs` diffs against them
bit-for-bit post-masking. The corpus format, the mask list, and the Rust runner
are already what S10 specifies, so the BMv2 runner replaces one producer of
`cases.json` and nothing else.

**Why:** BMv2 is a container-sized dependency for a milestone (M4) that this
build reaches by a different route. The property under test — "the Rust
pipeline agrees with an independent reading of the P4" — is tested today;
"independent" is simply weaker than "another implementation of P4".

## D3 — `FrameCtx` fields are accessors, not `pub`

**Spec:** S7.1 gives `FrameCtx` with public `data`, `len`, `headroom` fields.

**Here:** the fields are private with accessors, plus total `push_front` /
`pop_front` / `set_len` operations that return `Result`.

**Why:** `data: &mut [u8]` cannot express "there are also writable bytes
*before* this slice", which is exactly what `headroom` promises — a pipeline
holding `&mut [u8]` has no way to encapsulate into the headroom the spec says
it has. Making the window private and the operations total fixes that and makes
"frame longer than its buffer" unrepresentable rather than checked afterwards
(AGENTS.md rule 2). The field *names* and their meanings are unchanged.

## D4 — Two counters beyond the S9 list

**Spec:** S9 names the counter set exactly.

**Here:** `tx_unknown_port` and `tx_send_error` were added, both included in
`harness_drops`.

**Why:** S9's list has no name for a pipeline that forwards to a vport the
topology does not have, nor for a send that fails outright — and S1.6 requires
that *every* discard increment a named counter. Attribution (A5) is the product
requirement; leaving two discard paths unnamed would break it. Folding them
into an existing counter would be worse: it would misattribute them.

## D5 — `RX_BATCH` follows quinn-udp's cap

**Spec:** S6.2 — `RX_BATCH = 64` iovecs.

**Here:** `RX_BATCH = quinn_udp::BATCH_SIZE`, which is 32 on Linux.

**Why:** quinn-udp's `recv` caps at its own `BATCH_SIZE` internally, so slots
past that are never filled. At the slot size S6.2 mandates (`max GRO read`,
~92 KiB) the unused half is about 3 MiB of untouched memory per shard.

## D6 — `--tables`, `table load`, and a few control-plane conveniences

**Spec:** S8.2 lists `ping`, `info`, `counters`, `table-add`, `table-del`,
`table-dump`, `shutdown`.

**Here:** all of those, plus `tables` (print each table's key and actions from
the compiled schema), `table default` (set the miss action), `table clear`,
`table load <file>` (a batch), and `up4d --tables <file>` (the same batch at
startup). Batch and startup loading share one implementation and one file
format with `table-add`.

**Why:** the acceptance runs need a thousand routes installed (A2) and the
users are experimenters. None of it adds protocol: every one of these is the
same typed shim call the spec's commands make.

## D7 — Socket readiness is waited for with `poll`, not by blocking sockets

**Spec:** S1.2 — "std threads and blocking sockets only".

**Here:** the fabric socket stays non-blocking (as quinn-udp leaves it) and
`FabricSocket::recv`/`send` wait for readiness with `poll(2)` when the syscall
reports `EAGAIN`.

**Why:** `recvmmsg(2)` without `MSG_WAITFORONE` does not return when the first
message arrives — it waits for all `vlen` of them. quinn-udp passes no flags
and exposes none, so on a blocking socket a shard sits on 31 received frames
waiting for a 32nd, and the peer's queue backs up behind it. Leaving the socket
non-blocking without a readiness wait makes the loop a busy spin, which S6.3
forbids and which measurably starves the receivers this node is feeding.
Waiting on readiness and then asking for what has arrived is what a blocking
socket was wanted for; there is still no reactor, no runtime, and no callback.
