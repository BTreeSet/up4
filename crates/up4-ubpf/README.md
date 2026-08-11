# up4-ubpf

The `ubpf` backend: `p4/programs/*/*.ubpf.p4` compiled by `p4c --target ubpf` to
C, then by `clang -target bpf` to bytecode that up4 executes in process.

## Why this is a crate of its own

Same reason as `up4-x4c`: `up4-engine` is `#![forbid(unsafe_code)]`, and where
the target architecture has a JIT, executing it requires one `unsafe` call.
Confining that to a crate whose name says what it is keeps the engine pure.

## What to know

`src/generated/` holds both the C and the object. The C is what a person
reviews; the object is what `include_bytes!` embeds. Object-only would mean
reviewing a binary; C-only would mean needing clang to build up4.

Tables are *not* inside the VM. p4c emits calls to host helpers
(`ubpf_map_lookup` and friends, at fixed indices), so table state stays in
up4's own `Shared`/`Cached` structures and the existing control plane backs it
unchanged. Only match-action execution moves into the VM.

The JIT exists only where the **target** architecture supports one. Elsewhere
the variant does not exist at all, so there is no unsupported-mode error to
handle — see `ExecMode` in `up4-engine`'s catalog.

## Design notes for the VM (established, not yet built)

`elf.rs` is done: it loads either committed object and rewrites map references
to indices. What remains is the VM host, and three facts constrain it.

**The entry point takes two arguments.** p4c emits
`entry(void *ctx, struct standard_metadata *std_meta)`, so the program expects
`r1 = ctx` and `r2 = &std_meta`. No rbpf VM type sets two pointer registers
directly: `EbpfVmRaw` gives `r1 = mem, r2 = len`, and `EbpfVmMbuff` gives
`r1 = mbuff`, expecting the program to load its own pointers from the buffer
at fixed offsets. The fit is `EbpfVmMbuff` with a 16-byte mbuff holding
`[ctx, &std_meta]` and a two-instruction prologue prepended to the loaded text:

```text
ldxdw r2, [r1 + 8]   ; &std_meta
ldxdw r1, [r1 + 0]   ; ctx
```

Prepending is safe: BPF jumps and calls are relative to their own position, and
relocations are applied before the prologue is added.

**`ctx` is opaque.** The program never dereferences it; it calls
`ubpf_packet_data(ctx)` (helper 9) to obtain the packet address. So `ctx` can be
a token and the helper returns the real buffer, which keeps frame ownership on
the Rust side.

**A helper must read the key out of VM memory.** rbpf helpers are plain
`fn(u64, u64, u64, u64, u64) -> u64` with no context, so the table context
arrives through a thread-local, and the key pointer is a host address into
memory rbpf owns. Reading it requires one `unsafe` block — the same trust
uBPF's own C runtime takes, and the reason this crate is separate from
`up4-engine`. It needs a new `Warrant` in the allowlist; the returned value
pointer must live in a per-engine arena registered with
`register_allowed_memory`, so the VM can read the answer back.
