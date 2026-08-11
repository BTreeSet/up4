//! Counters (spec S9).
//!
//! Every discard in up4 is attributable: the harness-drop counters and the
//! pipeline's `engine_drop` are deliberately separate, because experiments must
//! be able to say *who* lost a frame (spec S9, A5).
//!
//! The registry is flat and named by closed enums rather than strings, so a
//! counter that exists cannot be misspelled at a bump site and a counter that
//! is added cannot be forgotten in the snapshot; [`Counter::ALL`] drives both.
//!
//! Memory ordering: hot-path bumps are `Relaxed` (a counter is a tally, not a
//! synchronization edge) and snapshot reads are `SeqCst`. A snapshot is
//! therefore *not* a consistent cut: counters are individually exact but their
//! relative order is explicitly not guaranteed.
//!
//! Cost: one relaxed fetch-add per bump; per-vport blocks are contiguous and
//! indexed by [`VportIdx`], so a shard touches one cache line per vport.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod snapshot;

pub use snapshot::{Bucket, HistogramSnapshot, Snapshot, SnapshotWriter, VportSnapshot};

use std::sync::atomic::{AtomicU64, Ordering};
use up4_config::{VportIdx, VportTable};

/// Node-wide counters.
///
/// The first six are *harness* drops: frames up4 itself refused. `EngineDrop`
/// is a pipeline decision and is never mixed in with them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(usize)]
pub enum Counter {
    /// Source tuple matched no configured vport (spec S6.2 step 3).
    RxUnknownPeer,
    /// Overlay header failed to decode (spec S6.2 step 4).
    RxBadHeader,
    /// Frame exceeded the fabric's inner MTU after the pipeline ran.
    TxOversizeDrop,
    /// Send would have blocked twice; the remainder was dropped.
    TxWouldBlock,
    /// A punt verdict arrived with no `[punt]` section configured.
    PuntUnconfiguredDrop,
    /// The punt queue was full.
    PuntOverflowDrop,
    /// A pipeline forwarded to a vport id the topology does not have. Not in
    /// spec S9's list, which has no name for it; up4's rule that every discard
    /// increments a *named* counter (S1.6) outranks leaving it unattributed.
    /// Recorded in `docs/deviations.md`.
    TxUnknownPort,
    /// A send failed for a reason other than "would block": a peer address
    /// that cannot be reached, a datagram the path refuses. Extension counter,
    /// same reasoning as `TxUnknownPort`.
    TxSendError,
    /// The pipeline decided to drop. Not a harness drop.
    EngineDrop,
    /// Batched receive syscalls issued.
    SyscallsRx,
    /// Send syscalls issued.
    SyscallsTx,
}

impl Counter {
    /// Every counter, in declaration order. Drives the snapshot.
    pub const ALL: [Self; 11] = [
        Self::RxUnknownPeer,
        Self::RxBadHeader,
        Self::TxOversizeDrop,
        Self::TxWouldBlock,
        Self::PuntUnconfiguredDrop,
        Self::PuntOverflowDrop,
        Self::TxUnknownPort,
        Self::TxSendError,
        Self::EngineDrop,
        Self::SyscallsRx,
        Self::SyscallsTx,
    ];

    /// The harness's own discards: everything up4 threw away that the
    /// pipeline did not ask it to. "Zero harness drops" (A1, A2) means the sum
    /// of exactly these.
    pub const HARNESS_DROPS: [Self; 8] = [
        Self::RxUnknownPeer,
        Self::RxBadHeader,
        Self::TxOversizeDrop,
        Self::TxWouldBlock,
        Self::PuntUnconfiguredDrop,
        Self::PuntOverflowDrop,
        Self::TxUnknownPort,
        Self::TxSendError,
    ];

    /// The wire name, exactly as spec S9 fixes it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::RxUnknownPeer => "rx_unknown_peer",
            Self::RxBadHeader => "rx_bad_header",
            Self::TxOversizeDrop => "tx_oversize_drop",
            Self::TxWouldBlock => "tx_would_block",
            Self::PuntUnconfiguredDrop => "punt_unconfigured_drop",
            Self::PuntOverflowDrop => "punt_overflow_drop",
            Self::TxUnknownPort => "tx_unknown_port",
            Self::TxSendError => "tx_send_error",
            Self::EngineDrop => "engine_drop",
            Self::SyscallsRx => "syscalls_rx",
            Self::SyscallsTx => "syscalls_tx",
        }
    }
}

/// Per-vport counters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(usize)]
pub enum VportCounter {
    /// Frames accepted on this vport.
    RxPkts,
    /// Inner bytes accepted on this vport.
    RxBytes,
    /// Frames transmitted on this vport.
    TxPkts,
    /// Inner bytes transmitted on this vport.
    TxBytes,
    /// Frames the pipeline broadcast, charged to the ingress vport.
    TxBroadcast,
    /// Total frames missing, summed over gaps (spec S6.2 step 5).
    RxSeqGapTotal,
    /// Frames that arrived behind the expectation.
    RxReorder,
}

impl VportCounter {
    /// Every per-vport counter, in declaration order.
    pub const ALL: [Self; 7] = [
        Self::RxPkts,
        Self::RxBytes,
        Self::TxPkts,
        Self::TxBytes,
        Self::TxBroadcast,
        Self::RxSeqGapTotal,
        Self::RxReorder,
    ];

    /// The wire name, exactly as spec S9 fixes it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::RxPkts => "rx_pkts",
            Self::RxBytes => "rx_bytes",
            Self::TxPkts => "tx_pkts",
            Self::TxBytes => "tx_bytes",
            Self::TxBroadcast => "tx_broadcast",
            Self::RxSeqGapTotal => "rx_seq_gap_total",
            Self::RxReorder => "rx_reorder",
        }
    }
}

/// The two I/O-shape histograms.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(usize)]
pub enum Hist {
    /// Segments coalesced into one receive (GRO effectiveness).
    GroSegmentsPerRead,
    /// Segments per transmit batch (GSO effectiveness).
    TxBatchSize,
}

impl Hist {
    /// Every histogram, in declaration order.
    pub const ALL: [Self; 2] = [Self::GroSegmentsPerRead, Self::TxBatchSize];

    /// The wire name, exactly as spec S9 fixes it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::GroSegmentsPerRead => "gro_segments_per_read",
            Self::TxBatchSize => "tx_batch_size",
        }
    }
}

/// Power-of-two histogram over `1,2,4,8,16,32,64`, plus an overflow bucket.
///
/// Cost: O(1), one `leading_zeros` and one relaxed fetch-add.
#[derive(Debug, Default)]
pub struct Histogram {
    buckets: [AtomicU64; Histogram::BUCKETS],
}

impl Histogram {
    /// Bucket upper bounds; the final bucket is unbounded.
    pub const BOUNDS: [u32; 7] = [1, 2, 4, 8, 16, 32, 64];
    const BUCKETS: usize = Self::BOUNDS.len() + 1;

    /// Record one observation. `0` is charged to the first bucket.
    #[inline]
    pub fn record(&self, value: usize) {
        let idx = match u32::try_from(value.max(1)) {
            Ok(v) if v <= 64 => v.ilog2() as usize,
            _ => Self::BOUNDS.len(),
        };
        // `idx <= BOUNDS.len()`, the last valid index of `buckets`.
        self.buckets[idx].fetch_add(1, Ordering::Relaxed);
    }

    /// Read every bucket.
    #[must_use]
    pub fn read(&self) -> [u64; Histogram::BUCKETS] {
        std::array::from_fn(|i| self.buckets[i].load(Ordering::SeqCst))
    }
}

/// One vport's contiguous counter block.
#[derive(Debug, Default)]
pub struct VportBlock {
    cells: [AtomicU64; VportCounter::ALL.len()],
}

impl VportBlock {
    /// Add `n` to one counter.
    #[inline]
    pub fn add(&self, c: VportCounter, n: u64) {
        self.cells[c as usize].fetch_add(n, Ordering::Relaxed);
    }

    /// Add one.
    #[inline]
    pub fn bump(&self, c: VportCounter) {
        self.add(c, 1);
    }

    /// Read one counter.
    #[must_use]
    pub fn get(&self, c: VportCounter) -> u64 {
        self.cells[c as usize].load(Ordering::SeqCst)
    }
}

/// The whole registry: shared by every shard and by the control channel.
#[derive(Debug)]
pub struct Metrics {
    node: String,
    global: [AtomicU64; Counter::ALL.len()],
    vports: Box<[VportBlock]>,
    vport_ids: Box<[u16]>,
    hists: [Histogram; Hist::ALL.len()],
}

impl Metrics {
    /// Allocate the registry for a topology. Done once, at startup.
    #[must_use]
    pub fn new(node: &str, vports: &VportTable) -> Self {
        Self {
            node: node.to_owned(),
            global: std::array::from_fn(|_| AtomicU64::new(0)),
            vports: (0..vports.len()).map(|_| VportBlock::default()).collect(),
            vport_ids: vports.iter().map(|(_, v)| v.id.get()).collect(),
            hists: std::array::from_fn(|_| Histogram::default()),
        }
    }

    /// Add `n` to a node-wide counter.
    #[inline]
    pub fn add(&self, c: Counter, n: u64) {
        self.global[c as usize].fetch_add(n, Ordering::Relaxed);
    }

    /// Add one to a node-wide counter.
    #[inline]
    pub fn bump(&self, c: Counter) {
        self.add(c, 1);
    }

    /// Read a node-wide counter.
    #[must_use]
    pub fn get(&self, c: Counter) -> u64 {
        self.global[c as usize].load(Ordering::SeqCst)
    }

    /// The counter block for a vport.
    ///
    /// Total: `idx` is a residency proof issued by the [`VportTable`] this
    /// registry was built from.
    #[inline]
    #[must_use]
    pub fn vport(&self, idx: VportIdx) -> &VportBlock {
        &self.vports[idx.get()]
    }

    /// A histogram.
    #[inline]
    #[must_use]
    pub fn hist(&self, h: Hist) -> &Histogram {
        &self.hists[h as usize]
    }

    /// Sum of every harness-drop counter, the quantity that must be zero in
    /// the acceptance runs (A1, A2).
    #[must_use]
    pub fn harness_drops(&self) -> u64 {
        Counter::HARNESS_DROPS.iter().map(|c| self.get(*c)).sum()
    }

    /// The node label carried in snapshots.
    #[must_use]
    pub fn node(&self) -> &str {
        &self.node
    }

    /// Configured vport ids, in index order.
    #[must_use]
    pub fn vport_ids(&self) -> &[u16] {
        &self.vport_ids
    }

    /// Per-vport counter blocks, in index order.
    #[must_use]
    pub fn vport_blocks(&self) -> &[VportBlock] {
        &self.vports
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table() -> VportTable {
        let src = r#"
[node]
id = "t"
bind = "127.0.0.1:1"
pipeline = "p"
ctl_socket = "/tmp/t.sock"
[[vport]]
id = 0
peer = "127.0.0.1:2"
[[vport]]
id = 9
peer = "127.0.0.1:3"
"#;
        up4_config::Config::from_toml(src, &["p"])
            .expect("fixture is valid")
            .vports
    }

    #[test]
    fn counter_names_are_the_spec_names() {
        let names: Vec<&str> = Counter::ALL.iter().map(|c| c.name()).collect();
        assert_eq!(
            names,
            [
                "rx_unknown_peer",
                "rx_bad_header",
                "tx_oversize_drop",
                "tx_would_block",
                "punt_unconfigured_drop",
                "punt_overflow_drop",
                "tx_unknown_port",
                "tx_send_error",
                "engine_drop",
                "syscalls_rx",
                "syscalls_tx",
            ]
        );
        let vnames: Vec<&str> = VportCounter::ALL.iter().map(|c| c.name()).collect();
        assert_eq!(
            vnames,
            [
                "rx_pkts",
                "rx_bytes",
                "tx_pkts",
                "tx_bytes",
                "tx_broadcast",
                "rx_seq_gap_total",
                "rx_reorder",
            ]
        );
    }

    #[test]
    fn engine_drop_is_not_a_harness_drop() {
        let m = Metrics::new("t", &table());
        m.bump(Counter::EngineDrop);
        assert_eq!(
            m.harness_drops(),
            0,
            "pipeline decisions never count as harness loss"
        );
        m.bump(Counter::RxBadHeader);
        assert_eq!(m.harness_drops(), 1);
    }

    #[test]
    fn per_vport_blocks_are_independent() {
        let t = table();
        let m = Metrics::new("t", &t);
        let a = t.idx_of_id(0).expect("configured");
        let b = t.idx_of_id(9).expect("configured");
        m.vport(a).add(VportCounter::RxPkts, 5);
        m.vport(b).add(VportCounter::RxPkts, 2);
        assert_eq!(m.vport(a).get(VportCounter::RxPkts), 5);
        assert_eq!(m.vport(b).get(VportCounter::RxPkts), 2);
    }

    #[test]
    fn histogram_buckets_are_powers_of_two_with_an_overflow() {
        let h = Histogram::default();
        for v in [0usize, 1, 2, 3, 4, 63, 64, 65, usize::MAX] {
            h.record(v);
        }
        // 0 and 1 -> bucket "1"; 2,3 -> "2"; 4 -> "4"; 63 -> "32"; 64 -> "64";
        // 65 and MAX -> overflow.
        assert_eq!(h.read(), [2, 2, 1, 0, 0, 1, 1, 2]);
    }
}
