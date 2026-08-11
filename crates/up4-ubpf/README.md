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
