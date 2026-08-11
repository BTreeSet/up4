//! up4's I/O shell (spec S6, S11.1, S12).
//!
//! Everything effectful lives here: sockets, the receive and transmit loops,
//! the capability probe, the clock, and signal handling. The crates below it
//! ([`up4_wire`], [`up4_config`], [`up4_engine`]) are pure and total, so this
//! is also the only place that can fail for reasons the type system cannot
//! rule out — and the only place `unsafe` is permitted (spec S1.7), confined to
//! four syscalls: `clock_gettime`, `uname`, `setsockopt`, and the
//! `pthread_sigmask`/`sigwait` pair. Each block carries the invariant it relies
//! on.
//!
//! No async runtime, no threads beyond the shards and the signal watcher, and
//! no allocation on the datapath after startup (spec S1.2, S6.4).

#![deny(missing_docs)]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod clock;
pub mod probe;
pub mod punt;
pub mod shard;
pub mod signal;
pub mod socket;
pub mod tx;
pub mod warn;

pub use probe::{Probe, probe};
pub use punt::{PUNT_DEPTH, PuntFrame, PuntQueue};
pub use shard::{Shard, ShardParams};
pub use signal::Stop;
pub use socket::{FabricSocket, HEADROOM, RX_BATCH, SocketCaps, TX_BATCH};
