//! up4's tools (spec S11).
//!
//! [`pktgen`] is a library first and a binary second, so the loopback
//! acceptance runs can drive it in-process: a test that spawns two nodes and
//! two generators is then one `cargo test`, with no orchestration to go wrong.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod frame;
pub mod pktgen;

pub use pktgen::{Latency, PktgenConfig, Report, run};
