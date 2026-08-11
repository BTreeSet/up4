//! The `ubpf` backend: P4 compiled to bytecode, executed in process.

#![deny(missing_docs)]

pub mod elf;
pub mod table;
pub mod vm;
