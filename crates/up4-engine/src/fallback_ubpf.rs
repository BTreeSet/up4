//! Fallback engine slot (spec S7.5): **not implemented in v1**.
//!
//! The intended route, recorded here so it is not rediscovered: `p4c-ubpf`
//! compiles a P4 program for the uBPF virtual machine, and `rbpf` can execute
//! BPF bytecode in-process, which together would give up4 a second pipeline
//! backend without x4c.
//!
//! The trap: **`p4c-ubpf` emits C**, not BPF bytecode. It targets the uBPF
//! runtime's C API, so the route needs a `clang -target bpf` step between the
//! P4 compiler and `rbpf`, a C toolchain at build time and a verifier-free
//! interpreter at run time. That is why it is a fallback and not the plan.
//!
//! Nothing is implemented here. The module exists so the seam is named and the
//! reasoning is attached to it.

// The `Engine` impl would live here:
//
// pub struct UbpfEngine { vm: rbpf::EbpfVmRaw, /* ... */ }
//
// impl crate::Engine for UbpfEngine {
//     fn process(&mut self, f: &mut crate::FrameCtx<'_>) -> crate::Verdict { ... }
//     fn name(&self) -> &'static str { "ubpf" }
// }
