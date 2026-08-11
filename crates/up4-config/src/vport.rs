//! The vport table: the topology, with both of its lookup directions prebuilt.

use crate::{VportId, error::ConfigError, error::Errors};
use std::{collections::HashMap, net::SocketAddr};

/// One virtual port: an id and the peer whose UDP tuple defines it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Vport {
    /// Configured id, as it appears in engine verdicts.
    pub id: VportId,
    /// Peer tuple: the transmit destination, and the receive demux key.
    pub peer: SocketAddr,
}

/// A dense index into a [`VportTable`], in `0..table.len()`.
///
/// This is a *capability*: the only way to obtain one is a successful lookup in
/// the table, so every per-vport array (counters, staging queues, sequence
/// trackers) can be indexed by it with a proof of residency rather than a
/// bounds check that must be justified at each site.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VportIdx(u16);

impl VportIdx {
    /// The index as a `usize`.
    #[inline]
    #[must_use]
    pub const fn get(self) -> usize {
        self.0 as usize
    }
}

/// The node's vports, indexed three ways.
///
/// Invariants, established by the only constructor and relied on everywhere
/// downstream: ids are unique and legal, peer tuples are unique, and every
/// [`VportIdx`] it hands out addresses a live entry.
///
/// Cost: id lookup O(1) through a dense array, peer lookup O(1) hashed, both
/// read-only after startup so the fast path never locks (spec S6.2).
#[derive(Clone, Debug)]
pub struct VportTable {
    entries: Box<[Vport]>,
    by_id: Box<[Option<VportIdx>]>,
    by_peer: HashMap<SocketAddr, VportIdx>,
}

impl VportTable {
    /// Build the table, recording uniqueness violations into `errs`.
    ///
    /// Returns `None` exactly when it recorded something: a partially valid
    /// topology is not a topology.
    pub(crate) fn build(entries: Vec<Vport>, errs: &mut Errors) -> Option<Self> {
        let before = errs.len();
        let mut by_peer: HashMap<SocketAddr, VportIdx> = HashMap::with_capacity(entries.len());
        let mut seen_id: HashMap<VportId, VportIdx> = HashMap::with_capacity(entries.len());

        for (slot, vp) in entries.iter().enumerate() {
            // `slot < entries.len() <= u16::MAX` is checked below before use.
            let Ok(slot16) = u16::try_from(slot) else {
                break;
            };
            let idx = VportIdx(slot16);
            if seen_id.insert(vp.id, idx).is_some() {
                errs.push(ConfigError::DuplicateVportId { value: vp.id.get() });
            }
            if let Some(first) = by_peer.insert(vp.peer, idx) {
                errs.push(ConfigError::DuplicatePeer {
                    value: vp.peer.to_string(),
                    // `first` and `idx` both index `entries`, which we are iterating.
                    first: entries[first.get()].id.get(),
                    second: vp.id.get(),
                });
            }
        }
        if errs.len() != before {
            return None;
        }

        let max_id = entries.iter().map(|v| v.id.get()).max()?;
        let mut by_id = vec![None; usize::from(max_id) + 1].into_boxed_slice();
        for (id, idx) in seen_id {
            by_id[usize::from(id.get())] = Some(idx);
        }
        Some(Self {
            entries: entries.into_boxed_slice(),
            by_id,
            by_peer,
        })
    }

    /// Number of vports.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Always false: [`VportTable::build`] rejects an empty topology.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Every vport with its index, in configuration order.
    pub fn iter(&self) -> impl Iterator<Item = (VportIdx, &Vport)> {
        self.entries
            .iter()
            .enumerate()
            .map(|(slot, vp)| (VportIdx(slot as u16), vp))
    }

    /// Resolve a raw id — an engine verdict's port number — to an index.
    ///
    /// Cost: O(1), one bounds-checked array read.
    #[inline]
    #[must_use]
    pub fn idx_of_id(&self, id: u16) -> Option<VportIdx> {
        self.by_id.get(usize::from(id)).copied().flatten()
    }

    /// Resolve a source tuple to the vport it arrived on (spec S6.2 step 3).
    ///
    /// Cost: O(1) hash lookup, no locking.
    #[inline]
    #[must_use]
    pub fn idx_of_peer(&self, peer: &SocketAddr) -> Option<VportIdx> {
        self.by_peer.get(peer).copied()
    }

    /// The vport at `idx`.
    ///
    /// Total: `idx` came from this table, and the table is immutable after
    /// construction, so the slot is live.
    #[inline]
    #[must_use]
    pub fn get(&self, idx: VportIdx) -> &Vport {
        &self.entries[idx.get()]
    }
}
