//! The pipeline layer (spec S7).
//!
//! up4's harness makes no forwarding decisions (spec S1.3). Everything about
//! *where a frame goes* lives behind two small contracts:
//!
//! * [`Engine`] — one per shard thread, invoked per frame, returns a
//!   [`Verdict`]. Frames are modified in place through a [`FrameCtx`].
//! * [`Pipeline`] — the shared, control-plane-facing half: it owns the tables
//!   and mints engines for shards.
//!
//! A P4 program becomes a `Pipeline` in one of two ways. The route this crate
//! *takes* today is a direct rendering of the program's parser, control, and
//! deparser onto the primitives in [`headers`] and [`table`] — P4 semantics in
//! Rust's type system, with the `.p4` source in `p4/programs/` as the artifact
//! of record (spec P1). The route the spec ultimately mandates is x4c-generated
//! code plugged into the same two contracts; [`x4c`] holds that seam, including
//! the byte-level ABI its adapter must satisfy. See `docs/deviations.md`.
//!
//! Cost: `Engine::process` is O(1) per frame for both compiled-in programs —
//! a fixed number of header loads plus one hashed table probe (l2fwd) or one
//! probe per populated prefix length (l3fwd). No allocation, ever.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod admission;
pub mod catalog;
pub mod fallback_ubpf;
pub mod frame;
pub mod headers;
pub mod programs;
pub mod shim;
pub mod table;
pub mod value;
pub mod x4c;

pub use frame::{FrameCtx, FrameError, MIN_HEADROOM};
pub use shim::{
    ActionDesc, ActionSchema, EntryDesc, KeyKind, NoTables, ParamDesc, ParamSchema, SchemaDesc,
    TableError, TableOps, TableSchema, TypedKey,
};
pub use value::{MacAddr, TypedVal, ValKind, ValueError};

/// What a pipeline decided about a frame (spec S7.1).
///
/// Closed: the harness matches exhaustively, and each arm maps to exactly one
/// dispatch path and one counter (spec S6.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Send on this vport id. The harness resolves the id; an id that is not
    /// configured is a harness drop, not a pipeline drop.
    Forward(u16),
    /// Send on every vport except the ingress one.
    Broadcast,
    /// Deliver to the control channel (spec S8.3).
    Punt,
    /// Discard. This is a *pipeline decision* and counts `engine_drop`.
    Drop,
}

/// A per-shard packet processor.
///
/// One instance per shard thread, so a pipeline may hold per-thread state
/// without synchronization; shared table state goes through
/// [`table::Shared`] instead (spec S7.3).
pub trait Engine: Send {
    /// Process one frame in place and decide its fate.
    fn process(&mut self, f: &mut FrameCtx<'_>) -> Verdict;

    /// The pipeline name this engine came from.
    fn name(&self) -> &'static str;
}

/// The shared half of a loaded pipeline: tables plus an engine factory.
pub trait Pipeline: Send + Sync {
    /// Program name, as registered.
    fn name(&self) -> &'static str;

    /// Mint an engine for one shard thread. Engines share this pipeline's
    /// tables; they do not copy them.
    fn engine(&self) -> Box<dyn Engine>;

    /// The control-plane surface.
    fn tables(&self) -> &dyn TableOps;
}

/// What a pipeline needs to know about the node it is loaded into.
///
/// Deliberately tiny: a pipeline may size a static port map from the topology,
/// but it learns nothing that would let it depend on the harness's behaviour.
#[derive(Clone, Debug)]
pub struct PipelineParams {
    /// Configured vport ids, in configuration order.
    pub vports: Box<[u16]>,
}

impl PipelineParams {
    /// Parameters for a node with these vports.
    #[must_use]
    pub fn new(vports: impl IntoIterator<Item = u16>) -> Self {
        Self {
            vports: vports.into_iter().collect(),
        }
    }
}

// The registry that used to live here is superseded by `catalog`: a name
// lookup that could fail became a closed `Selection` over `Program × Backend`,
// and the constructor moved to the crate above the backends (`up4d::pipeline`),
// because a pipeline layer cannot depend on the backends that depend on it.
