# Deviations from the spec

The spec (`docs/spec.md`) is the artifact of record. Where this implementation
departs from it, the departure is listed here with its reason. Nothing in this
file overrides the spec; it records where reality and the document disagree and
what was done about it.

## D1: Three backends, and generation is `cargo xtask`, not `build.rs`

**Spec:** S7.2: `build.rs` runs a pinned `x4c` over `p4/programs/*.p4` and the
adapter maps the generated `Pipeline` onto `Engine`.

**Here:** the `.p4` sources are the artifacts of record (spec P1) and three
backends execute them, all behind the same `Engine`/`Pipeline` contracts and
all selectable at configuration time (`up4_engine::catalog::Selection`):

| Backend | Where its code comes from |
| --- | --- |
| `native` | Hand-rendered Rust, block for block from the SoftNPU source |
| `x4c` | `x4c` output, committed under `crates/up4-x4c/src/generated/` |
| `ubpf` | `p4c --target ubpf` output, compiled to a BPF object and committed under `crates/up4-ubpf/src/generated/` |

Generation is a `cargo xtask` target, not `build.rs`, and its output is checked
in rather than produced during the build.

**Why not `build.rs`:** both compilers are large native builds (p4c needs
bison, flex, boost and a C++ toolchain), and a `build.rs` that shells out to
them makes every `cargo build`, on every machine and every CI job, depend on
provisioning them. Committing the output instead means the normal build needs
nothing but `cargo`, and the compilers are needed only when a `.p4` changes.

**What keeps the committed output honest:** `cargo xtask audit` hashes every
`.p4` against `p4/generated.lock` and fails if a source moved without its
artifacts (97 ms, no compiler, runs on every CI job); `cargo xtask verify`
rebuilds both compilers in a self-contained userspace toolchain and diffs the
result (weekly, and on demand). See `xtask/README.md`.

**Why `native` still exists:** it is the only backend with no per-frame
allocation (D9) and the one the throughput acceptance runs against. Keeping it
also makes the conformance corpus a three-way check rather than a two-way one.

## D2: The BMv2 differential runner is not wired

**Spec:** S10: `tools/bmv2-diff/` replays each corpus through BMv2 in a CI
container and writes the expectations file.

**Here:** `tools/corpus/gen_corpus.py` produces the expectations from an
independent model of the P4 source, and
`crates/up4-catalog/tests/conformance.rs` diffs against them bit-for-bit
post-masking, for **every** backend, not just one.

**Why:** BMv2 is a container-sized dependency. What S10 wants from it is
independent confirmation that up4 reads the `.p4` correctly, and the three
backends now supply a good deal of that on their own: two of them are the
output of real P4 compilers, sharing no code with the renderings or with each
other (and, in the uBPF case, not even a language). A misreading of the source
has to be made identically by a hand-rendering, by `x4c`, and by `p4c` to go
unnoticed. That is weaker than BMv2, since all three could inherit a
misreading of the *spec*, but it is much stronger than one implementation
against one model.

## D3: `FrameCtx` fields are accessors, not `pub`

**Spec:** S7.1 gives `FrameCtx` with public `data`, `len`, `headroom` fields.

**Here:** the fields are private with accessors, plus total `push_front` /
`pop_front` / `set_len` operations that return `Result`.

**Why:** `data: &mut [u8]` cannot express "there are also writable bytes
*before* this slice", which is exactly what `headroom` promises. A pipeline
holding `&mut [u8]` has no way to encapsulate into the headroom the spec says
it has. Making the window private and the operations total fixes that and makes
"frame longer than its buffer" unrepresentable rather than checked afterwards
(AGENTS.md rule 2). The field *names* and their meanings are unchanged.

## D4: Two counters beyond the S9 list

**Spec:** S9 names the counter set exactly.

**Here:** `tx_unknown_port` and `tx_send_error` were added, both included in
`harness_drops`.

**Why:** S9's list has no name for a pipeline that forwards to a vport the
topology does not have, nor for a send that fails outright, and S1.6 requires
that *every* discard increment a named counter. Attribution (A5) is the product
requirement; leaving two discard paths unnamed would break it. Folding them
into an existing counter would be worse: it would misattribute them.

## D5: `RX_BATCH` follows quinn-udp's cap

**Spec:** S6.2: `RX_BATCH = 64` iovecs.

**Here:** `RX_BATCH = quinn_udp::BATCH_SIZE`, which is 32 on Linux.

**Why:** quinn-udp's `recv` caps at its own `BATCH_SIZE` internally, so slots
past that are never filled. At the slot size S6.2 mandates (`max GRO read`,
~92 KiB) the unused half is about 3 MiB of untouched memory per shard.

## D6: `--tables`, `table load`, and a few control-plane conveniences

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

## D7: Socket readiness is waited for with `poll`, not by blocking sockets

**Spec:** S1.2: "std threads and blocking sockets only".

**Here:** the fabric socket stays non-blocking (as quinn-udp leaves it) and
`FabricSocket::recv`/`send` wait for readiness with `poll(2)` when the syscall
reports `EAGAIN`.

**Why:** `recvmmsg(2)` without `MSG_WAITFORONE` does not return when the first
message arrives; it waits for all `vlen` of them. quinn-udp passes no flags
and exposes none, so on a blocking socket a shard sits on 31 received frames
waiting for a 32nd, and the peer's queue backs up behind it. Leaving the socket
non-blocking without a readiness wait makes the loop a busy spin, which S6.3
forbids and which measurably starves the receivers this node is feeding.
Waiting on readiness and then asking for what has arrived is what a blocking
socket was wanted for; there is still no reactor, no runtime, and no callback.

## D8: `up4-x4c` depends on `p4rs` by git revision

**Spec:** S1.3: dependencies are published crates at pinned versions.

**Here:** `crates/up4-x4c/Cargo.toml` takes `p4rs` from
`github.com/oxidecomputer/p4` at rev `e29b7953`. It is not published to
crates.io.

**Why:** `p4rs` is x4c's runtime library, the library the generated code calls
into, so the only correct version is the one matching the compiler that
produced the
code. `xtask/src/tool.rs` pins the same revision for the compiler, and the two
pins are meant to be read and moved together. A published version would not
help even if one existed: it would still have to match the compiler rev.

**Contained by:** the dependency is confined to `up4-x4c`. Nothing else in the
workspace links `p4rs`, so `native` and `ubpf` are unaffected by it, and a
build that selects neither still resolves it only because Cargo resolves the
whole workspace.

## D9: The `x4c` backend allocates per frame

**Spec:** S13.5: the fast path performs no heap allocation, proven by a
counting allocator.

**Here:** true of `native` and `ubpf`; **not** true of `x4c`, which is
declared as `AllocProfile::PerFrame` in `Backend::facts()` and reported by
`up4ctl info`.

**Why:** x4c's runtime models every header field as a heap `BitVec` and its
generated pipeline returns a `Vec` of outputs per packet. That is upstream's
ABI, not a choice this repository makes; honouring it is what "true P4, by a
real P4 compiler" costs here.

**Why it is declared rather than fixed:** rewriting it means forking x4c's code
generator. The alternative, quietly letting S13.5's claim become false for one
backend, is worse than saying so in the type. The allocation guard therefore
runs against the backends that claim `AllocProfile::None`, and the claim is
per-backend rather than global.

## D10: Ingress admission refuses frames the `.p4` would forward

**Spec:** P1: the `.p4` source is the artifact of record; a backend's
behaviour is the program's behaviour.

**Here:** `up4_engine::admission::Admission` runs before the program. `l3fwd`
declares `CoherentIpv4`, which refuses a frame announcing `ethertype == 0x0800`
whose IPv4 header contradicts itself: a version other than 4, or a header
length below the legal minimum or past the captured bytes. Neither
`l3fwd.softnpu.p4` nor `l3fwd.ubpf.p4` contains such a check, so all three
backends refuse strictly more than the source says.

**Why:** a P4 parser rejects when `extract` runs out of bytes and for no other
reason; it never checks that the bytes it took agree with each other. A router
acts on that header, and a well-formed packet never reaches the check, so
refusing at ingress is cheaper than carrying a self-contradictory header
through a table lookup and a rewrite. It also cannot be written in the source:
`x4c` compiles no construct that would express it.

**Why it is not in a backend:** three renderings of one program that refuse
different frames are three programs. `Admission` is declared on the `Program`
and composed with whichever backend runs it:
`up4(program) = admit(program) ; p4(program)`. The deviation is therefore one
statement in one place, applied uniformly. `l2fwd` declares `Everything`: a
bridge forwards on MAC addresses and has no opinion about the payload.

**What holds it:** `admission_binds_every_backend_of_a_program` walks all 256
values of the IPv4 version/IHL byte against all three backends;
`fusion_is_sound_for_every_version_and_ihl` proves the `native` parser computes
the check itself, which is why `build` does not wrap it twice.

## D11: The `ubpf` backend JIT-compiles, giving up rbpf's memory checking

**Spec:** S1.7: `unsafe` is confined and each use is bounded by a stated
argument.

**Here:** on x86-64, `Vm::new` calls rbpf's `jit_compile` and every frame runs
`execute_program_jit`. On every other target `ExecMode::Jit` does not exist:
the variant is `#[cfg(target_arch = "x86_64")]`, so no code can select it and
no runtime check has to refuse it. `up4ctl info` reports the mode in force, and
`reported_mode_is_the_mode_that_runs` holds `Backend::facts()` equal to what
`Vm::mode()` says for every shipped program.

**What is given up:** `register_allowed_memory`, which bounds every load and
store the *interpreter* makes into the VM's buffers, is an interpreter feature.
rbpf's JIT ignores it and performs no runtime memory checking whatsoever. Under
`ExecMode::Jit` the only thing keeping generated code inside its buffers is the
bounds checking p4c already emits against `packet_length`, which up4 supplies
and controls.

**Why that is accepted:** it is the bargain in-kernel eBPF makes, one static
argument in place of a dynamic check, and up4's testbed is x86-64, where
interpreting costs what an interpreter costs. The decision is deliberate rather
than inherited from a default, which is why the mode is a closed sum keyed on
the target architecture rather than a boolean.

**What bounds it instead:**

- The corpus runs through **every** `ExecMode` the target has, not just the
  default: `runners()` in `crates/up4-catalog/tests/conformance.rs` replays
  every case through JIT-compiled machine code and through the interpreter, and
  requires the same verdicts and the same bytes. "The interpreter agrees" is
  not evidence about the JIT, so the JIT is tested as its own execution.
- CI runs on `ubuntu-latest`, which is x86-64, so that is the mode CI exercises
  by default.
- rbpf emits into a single 4 KiB page and overflowing it panics, fatally
  under `panic = "abort"`. Both shipped programs fit today (`l2fwd` is 86
  instructions, `l3fwd` 229), and
  `every_shipped_program_compiles_in_every_mode` turns growing past the page
  into a red test rather than an abort at startup.
- Compilation happens once, in `Vm::new`, after the helpers are registered;
  the JIT resolves their addresses at compile time, so a helper registered
  afterwards would be invisible to the emitted code.
- The two new `unsafe` sites are on the audit allowlist
  (`crates/up4d/tests/unsafe_audit.rs`) under the `VmBoundary` warrant, with
  this deviation as their reason.

## D12: `x4c` tables have no default-action setter

**Spec:** S8.2: `table default` sets a table's miss action.

**Here:** the `x4c` backend answers
`TableError::Unsupported { table, reason }`. `native` and `ubpf` implement it.

**Why:** x4c's generated table type exposes entry insertion and removal and
nothing else; the default action is fixed by `default_action =` in the source.
A backend that silently ignored the call, or one that faked it by inserting a
catch-all entry, would report success for something that did not happen.
`Unsupported` is a variant of the error the control plane already handles, so
`up4ctl` prints the reason and exits non-zero.

## D13: The `x4c` adapter guards a short-frame panic in `p4rs`

**Spec:** P1: a P4 parser that runs out of bytes rejects the packet.

**Here:** `p4rs`'s `packet_in::extract` slices unconditionally, so extracting a
14-byte Ethernet header from a 13-byte frame panics
(`range end index 14 out of range`) rather than rejecting. Under
`panic = "abort"` that ends the process, and it is remotely reachable from a
single short packet. `crates/up4-x4c/src/pipeline.rs` therefore carries a
per-program
`min_parse` (14 for `l2fwd`, 34 for `l3fwd`) and drops a shorter frame before
calling in.

**Why here and not upstream:** the guard restores exactly the semantics the
source already specifies, so it changes no accepted frame; the conformance
corpus covers both truncation cases on all three backends. It is a workaround
for an upstream defect, not a behaviour of up4's, and should be deleted if
`p4rs` starts rejecting instead of panicking.

