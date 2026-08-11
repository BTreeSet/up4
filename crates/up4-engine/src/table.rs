//! The match-action core: the two match kinds up4's v1 programs use, and the
//! publication discipline that lets the control plane rewrite them while
//! packets are in flight.
//!
//! P4 tables are values here, not objects: an update builds a new table and
//! publishes it ([`Shared::update`]), and each shard reads through a
//! [`Cached`] handle that refreshes only when the version changes. So the fast
//! path pays one relaxed atomic load per lookup and never takes a lock, while
//! the control plane never mutates a structure a packet might be reading.
//!
//! Consistency model (spec S7.3): a control operation is atomic — a packet
//! sees the table entirely before or entirely after it — and a *batch* of
//! operations is not, since each publishes separately. Visibility is bounded by
//! one lookup, comfortably inside A4's 100 ms.

use std::{
    collections::HashMap,
    hash::Hash,
    net::Ipv4Addr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

/// A value published to shard threads, versioned so readers can skip the lock.
#[derive(Debug)]
pub struct Shared<T> {
    version: AtomicU64,
    current: Mutex<Arc<T>>,
}

impl<T> Shared<T> {
    /// Publish an initial value.
    pub fn new(value: T) -> Self {
        Self {
            version: AtomicU64::new(0),
            current: Mutex::new(Arc::new(value)),
        }
    }

    /// The current value.
    ///
    /// Cost: one uncontended lock. Control plane only.
    pub fn load(&self) -> Arc<T> {
        Arc::clone(&self.lock())
    }

    /// Replace the value with `f` applied to the current one, and publish.
    ///
    /// Copy-on-write: `f` sees an immutable snapshot and returns the successor,
    /// so no reader can observe a half-applied update.
    pub fn update<R>(&self, f: impl FnOnce(&T) -> (T, R)) -> R {
        let mut slot = self.lock();
        let (next, out) = f(&slot);
        *slot = Arc::new(next);
        // Release pairs with the Acquire in `Cached::get`: a reader that sees
        // this version also sees the value stored above.
        self.version.fetch_add(1, Ordering::Release);
        out
    }

    /// How many times the value has been replaced.
    pub fn version(&self) -> u64 {
        self.version.load(Ordering::Acquire)
    }

    /// A poisoned table lock means a control operation panicked mid-update.
    /// The value is still a fully constructed `Arc<T>` — the update either
    /// completed or never stored — so recovering is sound and beats taking the
    /// datapath down.
    fn lock(&self) -> std::sync::MutexGuard<'_, Arc<T>> {
        self.current.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// A shard-local view of a [`Shared`] value.
///
/// Cost: one `Acquire` load and a compare per access; an `Arc` clone only on
/// the packet that first observes a control-plane change.
#[derive(Debug)]
pub struct Cached<T> {
    value: Arc<T>,
    version: u64,
}

impl<T> Cached<T> {
    /// Take a view of the current value.
    pub fn new(shared: &Shared<T>) -> Self {
        // Read the version first: a concurrent update between these two lines
        // makes the view stale by one, which the next `get` repairs.
        let version = shared.version();
        Self {
            value: shared.load(),
            version,
        }
    }

    /// The value, refreshed if the control plane has published since last time.
    #[inline]
    pub fn get(&mut self, shared: &Shared<T>) -> &T {
        let version = shared.version.load(Ordering::Acquire);
        if version != self.version {
            self.value = shared.load();
            self.version = version;
        }
        &self.value
    }
}

/// An exact-match table with a default action (P4 `key = { x: exact; }`).
///
/// Cost: O(1) hashed lookup.
#[derive(Clone, Debug)]
pub struct ExactTable<K, A> {
    entries: HashMap<K, A>,
    default_action: A,
}

impl<K: Eq + Hash + Clone, A: Clone> ExactTable<K, A> {
    /// An empty table whose misses take `default_action`.
    pub fn new(default_action: A) -> Self {
        Self {
            entries: HashMap::new(),
            default_action,
        }
    }

    /// The action for `key`: the matched entry, or the default.
    ///
    /// This *is* P4 table application; there is no other outcome.
    #[inline]
    pub fn apply(&self, key: &K) -> &A {
        self.entries.get(key).unwrap_or(&self.default_action)
    }

    /// The matched entry only, for control-plane queries.
    pub fn get(&self, key: &K) -> Option<&A> {
        self.entries.get(key)
    }

    /// Insert or replace, returning whether an entry was replaced.
    pub fn insert(&mut self, key: K, action: A) -> bool {
        self.entries.insert(key, action).is_some()
    }

    /// Remove, returning whether an entry existed.
    pub fn remove(&mut self, key: &K) -> bool {
        self.entries.remove(key).is_some()
    }

    /// Replace the default action.
    pub fn set_default(&mut self, action: A) {
        self.default_action = action;
    }

    /// The default action.
    pub fn default_action(&self) -> &A {
        &self.default_action
    }

    /// Number of installed entries, excluding the default.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether any entry is installed.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Drop every entry, returning how many were removed.
    pub fn clear(&mut self) -> usize {
        let n = self.entries.len();
        self.entries.clear();
        n
    }

    /// Every installed entry.
    pub fn iter(&self) -> impl Iterator<Item = (&K, &A)> {
        self.entries.iter()
    }
}

/// An IPv4 prefix in canonical form: host bits are cleared by construction, so
/// `10.0.0.5/24` and `10.0.0.0/24` are the same value and a table cannot hold
/// two entries that mean the same route.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Ipv4Prefix {
    base: u32,
    len: u8,
}

impl Ipv4Prefix {
    /// Build a prefix, rejecting lengths above 32 and canonicalizing the base.
    #[must_use]
    pub const fn new(addr: Ipv4Addr, len: u8) -> Option<Self> {
        if len > 32 {
            return None;
        }
        Some(Self {
            base: u32::from_be_bytes(addr.octets()) & mask_of(len),
            len,
        })
    }

    /// The canonical network address.
    #[must_use]
    pub const fn addr(self) -> Ipv4Addr {
        Ipv4Addr::new(
            (self.base >> 24) as u8,
            (self.base >> 16) as u8,
            (self.base >> 8) as u8,
            self.base as u8,
        )
    }

    /// The prefix length in bits.
    ///
    /// Named `prefix_len` rather than `len`: a prefix has no elements to count,
    /// and the shorter name invites the wrong mental model.
    #[must_use]
    pub const fn prefix_len(self) -> u8 {
        self.len
    }

    /// Whether this is the default route, `0.0.0.0/0`.
    #[must_use]
    pub const fn is_default_route(self) -> bool {
        self.len == 0
    }
}

impl std::fmt::Display for Ipv4Prefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr(), self.len)
    }
}

/// The mask with `len` leading ones. `len <= 32` is the caller's obligation;
/// `32 - 32 = 0` shifts are legal, and the `len == 0` case is spelled out
/// because `u32 >> 32` is undefined.
const fn mask_of(len: u8) -> u32 {
    if len == 0 { 0 } else { u32::MAX << (32 - len) }
}

/// A longest-prefix-match table (P4 `key = { x: lpm; }`).
///
/// Entries are grouped by prefix length, longest first, so a lookup is one
/// hashed probe per *distinct populated length* — at most 33, and in practice
/// the handful of lengths a routing table actually uses (a 1 000-route table of
/// /24s and /32s probes twice). That beats a 32-step trie walk on the access
/// pattern up4 has: a small, static route set read at line rate.
#[derive(Clone, Debug)]
pub struct LpmTable<A> {
    /// Invariant: strictly decreasing `len`, no empty group.
    groups: Vec<LpmGroup<A>>,
    default_action: A,
}

#[derive(Clone, Debug)]
struct LpmGroup<A> {
    len: u8,
    mask: u32,
    entries: HashMap<u32, A>,
}

impl<A: Clone> LpmTable<A> {
    /// An empty table whose misses take `default_action`.
    pub fn new(default_action: A) -> Self {
        Self {
            groups: Vec::new(),
            default_action,
        }
    }

    /// The action for `addr`: the longest matching prefix, or the default.
    ///
    /// Cost: O(distinct populated prefix lengths) hashed probes.
    #[inline]
    pub fn apply(&self, addr: Ipv4Addr) -> &A {
        let key = u32::from_be_bytes(addr.octets());
        self.groups
            .iter()
            .find_map(|g| g.entries.get(&(key & g.mask)))
            .unwrap_or(&self.default_action)
    }

    /// Insert or replace a route, returning whether one was replaced.
    pub fn insert(&mut self, prefix: Ipv4Prefix, action: A) -> bool {
        let pos = match self.groups.binary_search_by(|g| prefix.len.cmp(&g.len)) {
            Ok(pos) => pos,
            Err(pos) => {
                self.groups.insert(
                    pos,
                    LpmGroup {
                        len: prefix.len,
                        mask: mask_of(prefix.len),
                        entries: HashMap::new(),
                    },
                );
                pos
            }
        };
        self.groups[pos]
            .entries
            .insert(prefix.base, action)
            .is_some()
    }

    /// Remove a route, returning whether it existed.
    pub fn remove(&mut self, prefix: Ipv4Prefix) -> bool {
        let Ok(pos) = self.groups.binary_search_by(|g| prefix.len.cmp(&g.len)) else {
            return false;
        };
        let removed = self.groups[pos].entries.remove(&prefix.base).is_some();
        if self.groups[pos].entries.is_empty() {
            self.groups.remove(pos);
        }
        removed
    }

    /// Replace the default action.
    pub fn set_default(&mut self, action: A) {
        self.default_action = action;
    }

    /// The default action.
    pub fn default_action(&self) -> &A {
        &self.default_action
    }

    /// Number of installed routes.
    pub fn len(&self) -> usize {
        self.groups.iter().map(|g| g.entries.len()).sum()
    }

    /// Whether any route is installed.
    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }

    /// Drop every route, returning how many were removed.
    pub fn clear(&mut self) -> usize {
        let n = self.len();
        self.groups.clear();
        n
    }

    /// Every route, longest prefix first.
    pub fn iter(&self) -> impl Iterator<Item = (Ipv4Prefix, &A)> {
        self.groups.iter().flat_map(|g| {
            g.entries.iter().map(|(base, a)| {
                (
                    Ipv4Prefix {
                        base: *base,
                        len: g.len,
                    },
                    a,
                )
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_table_falls_through_to_the_default_action() {
        let mut t: ExactTable<u8, &str> = ExactTable::new("miss");
        assert_eq!(*t.apply(&1), "miss");
        assert!(!t.insert(1, "hit"));
        assert!(t.insert(1, "hit again"));
        assert_eq!(*t.apply(&1), "hit again");
        assert!(t.remove(&1));
        assert!(!t.remove(&1));
        assert_eq!(*t.apply(&1), "miss");
    }

    #[test]
    fn prefixes_are_canonical_and_bounded() {
        let p = Ipv4Prefix::new(Ipv4Addr::new(10, 1, 2, 3), 24).expect("len <= 32");
        assert_eq!(p.to_string(), "10.1.2.0/24");
        assert_eq!(
            p,
            Ipv4Prefix::new(Ipv4Addr::new(10, 1, 2, 0), 24).expect("len <= 32")
        );
        assert_eq!(Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 33), None);
        let d = Ipv4Prefix::new(Ipv4Addr::new(1, 2, 3, 4), 0).expect("len <= 32");
        assert!(d.is_default_route());
        assert_eq!(d.to_string(), "0.0.0.0/0");
    }

    fn prefix(s: &str, len: u8) -> Ipv4Prefix {
        Ipv4Prefix::new(s.parse().expect("literal"), len).expect("len <= 32")
    }

    #[test]
    fn lpm_prefers_the_longest_match_whatever_the_insertion_order() {
        let mut t: LpmTable<&str> = LpmTable::new("default");
        t.insert(prefix("10.0.0.0", 8), "/8");
        t.insert(prefix("10.0.0.0", 24), "/24");
        t.insert(prefix("0.0.0.0", 0), "/0");
        t.insert(prefix("10.0.0.7", 32), "/32");

        assert_eq!(*t.apply("10.0.0.7".parse().expect("literal")), "/32");
        assert_eq!(*t.apply("10.0.0.8".parse().expect("literal")), "/24");
        assert_eq!(*t.apply("10.0.1.1".parse().expect("literal")), "/8");
        assert_eq!(*t.apply("11.0.0.1".parse().expect("literal")), "/0");
    }

    #[test]
    fn lpm_removal_drops_empty_length_groups_and_restores_shorter_matches() {
        let mut t: LpmTable<&str> = LpmTable::new("default");
        t.insert(prefix("10.0.0.0", 8), "/8");
        t.insert(prefix("10.0.0.0", 24), "/24");
        assert!(t.remove(prefix("10.0.0.0", 24)));
        assert!(!t.remove(prefix("10.0.0.0", 24)));
        assert_eq!(*t.apply("10.0.0.1".parse().expect("literal")), "/8");
        assert_eq!(t.len(), 1);
        assert_eq!(t.clear(), 1);
        assert_eq!(*t.apply("10.0.0.1".parse().expect("literal")), "default");
    }

    #[test]
    fn lpm_scales_to_a_thousand_routes() {
        let mut t: LpmTable<u32> = LpmTable::new(u32::MAX);
        for i in 0..1000u32 {
            let addr = Ipv4Addr::from(0x0a00_0000 | (i << 8));
            t.insert(Ipv4Prefix::new(addr, 24).expect("len <= 32"), i);
        }
        assert_eq!(t.len(), 1000);
        assert_eq!(*t.apply(Ipv4Addr::from(0x0a00_0000 | (999 << 8) | 5)), 999);
        assert_eq!(*t.apply(Ipv4Addr::from(0x0b00_0000)), u32::MAX);
        assert_eq!(t.iter().count(), 1000);
    }

    #[test]
    fn readers_observe_updates_and_nothing_in_between() {
        let shared = Shared::new(ExactTable::<u8, &str>::new("miss"));
        let mut cached = Cached::new(&shared);
        assert_eq!(*cached.get(&shared).apply(&1), "miss");

        shared.update(|t| {
            let mut next = t.clone();
            next.insert(1, "hit");
            (next, ())
        });
        assert_eq!(*cached.get(&shared).apply(&1), "hit");
        assert_eq!(shared.version(), 1);
    }

    #[test]
    fn a_cached_view_survives_concurrent_updates() {
        let shared = Arc::new(Shared::new(ExactTable::<u32, u32>::new(0)));
        let writer = {
            let shared = Arc::clone(&shared);
            std::thread::spawn(move || {
                for i in 1..=200u32 {
                    shared.update(|t| {
                        let mut next = t.clone();
                        next.insert(i, i);
                        (next, ())
                    });
                }
            })
        };
        let mut cached = Cached::new(&shared);
        let mut last = 0;
        for _ in 0..20_000 {
            let n = cached.get(&shared).len() as u32;
            assert!(n >= last, "a reader never goes backwards");
            last = n;
        }
        writer.join().expect("writer thread");
        assert_eq!(cached.get(&shared).len(), 200);
    }
}
