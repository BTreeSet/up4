//! up4's control channel (spec S8).
//!
//! A node's entire control surface is one `SOCK_SEQPACKET` socket speaking
//! length-prefixed JSON: liveness, build and topology info, counter snapshots,
//! table reads and writes, punt drain, and graceful shutdown. There is no
//! authentication because there is no network exposure: the socket is mode
//! 0600 and the filesystem is the boundary (spec S8.1).
//!
//! Table writes carry the text an operator typed and are refined against the
//! pipeline's own P4-derived schema on arrival, so the control plane has
//! exactly one place where untrusted text becomes typed values.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod b64;
pub mod client;
pub mod codec;
pub mod protocol;
pub mod server;

pub use client::Client;
pub use protocol::{
    EntryBatch, EntrySpec, Info, Params, PuntedFrame, Request, Response, VportInfo,
};
pub use server::{Context, PUNT_DRAIN_MAX, Server, apply_entries, handle};

#[cfg(test)]
mod tests;
