//! The tables the bytecode looks up, kept on the Rust side.
//!
//! p4c's generated code reaches a table through `ubpf_map_lookup(map, key)`,
//! a *host* call. So the VM never owns table state: it hands over a map index
//! and a key, and gets back the bytes of a value. Everything about how a table
//! is stored, published, and mutated stays here, in Rust, behind up4's usual
//! copy-on-write publication.
//!
//! What crosses the boundary is only a byte image, and its layout is dictated
//! by the C structs p4c emits (`crates/up4-ubpf/src/generated/*.h`). [`Layout`]
//! names those layouts so the encoding is stated once and tested, rather than
//! spread through the helper as magic offsets.

use std::collections::BTreeMap;

/// A key or value as the bytecode sees it: a fixed-width little-endian image
/// of a C struct.
pub type Bytes = Vec<u8>;

/// How one table's key and value are laid out in the compiled program.
///
/// Derived from the generated header, and checked against it by
/// `layouts_match_the_generated_header`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    /// Key width in bytes.
    pub key: usize,
    /// Value width in bytes.
    pub value: usize,
    /// Byte offset of the action discriminant within the value.
    pub action_at: usize,
    /// Byte offset of the action's parameter block within the value.
    pub params_at: usize,
    /// The slice of the key image that participates in matching.
    ///
    /// p4c's LPM key is `{ uint32_t prefix_len0; uint32_t field; }` and the
    /// generated code zero-initialises the struct and sets only the field —
    /// the prefix length is the *host's* to supply, because the host does the
    /// prefix search. So matching reads a window of the key, not all of it.
    pub match_at: usize,
    /// Width of that window.
    pub match_len: usize,
}

/// Both shipped programs use the same shape: a single scalar key, a 4-byte
/// action discriminant, then the parameter union.
///
/// `pipe_<table>_value` is `{ enum action; union u; }`, and C aligns the union
/// to its widest member; for both programs that is 4, so the parameters start
/// at offset 4.
/// Byte offset of the action discriminant in a value image.
pub const VALUE_ACTION_AT: usize = 0;
/// Byte offset of the action parameter block in a value image.
pub const VALUE_PARAMS_AT: usize = 4;

impl Layout {
    /// A layout for a scalar-keyed table with `key` bytes of key and `params`
    /// bytes of action parameters.
    #[must_use]
    pub const fn scalar(key: usize, params: usize) -> Self {
        Self {
            key,
            // C rounds the struct up to its alignment, which is the 4 of the
            // discriminant.
            value: VALUE_PARAMS_AT + params.next_multiple_of(4),
            action_at: VALUE_ACTION_AT,
            params_at: VALUE_PARAMS_AT,
            match_at: 0,
            match_len: key,
        }
    }

    /// A layout stated field by field, for a table whose value union forces
    /// padding a formula would get wrong (l3fwd's `forward(bit<16>, bit<48>)`
    /// aligns its union to 8).
    #[must_use]
    pub const fn explicit(
        key: usize,
        value: usize,
        params_at: usize,
        match_at: usize,
        match_len: usize,
    ) -> Self {
        Self {
            key,
            value,
            action_at: VALUE_ACTION_AT,
            params_at,
            match_at,
            match_len,
        }
    }

    /// Build the value image for `action` with `params` already encoded.
    #[must_use]
    pub fn value(&self, action: u32, params: &[u8]) -> Bytes {
        let mut v = vec![0u8; self.value];
        v[self.action_at..self.action_at + 4].copy_from_slice(&action.to_le_bytes());
        let n = params.len().min(self.value - self.params_at);
        v[self.params_at..self.params_at + n].copy_from_slice(&params[..n]);
        v
    }
}

/// How a table matches.
///
/// Closed, and mirrors the two map types p4c's uBPF backend emits
/// (`UBPF_MAP_TYPE_HASHMAP` and `UBPF_MAP_TYPE_LPM_TRIE`); no other match kind
/// reaches this backend, because the compiler refuses it first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Match {
    /// Whole-key equality.
    Exact,
    /// Longest prefix over the leading `bits` of the key, most significant
    /// first, with the prefix length carried alongside each entry.
    Lpm,
}

/// The widest key window this backend matches on, and the size of the stack
/// buffer an LPM probe masks into.
///
/// Both shipped programs are far under it (8 bytes for `l2fwd`'s MAC, 4 for
/// `l3fwd`'s IPv4 address). [`Table::new`] refuses a wider layout rather than
/// truncating one, so the read path can use a fixed buffer and never allocate.
pub const MAX_MATCH_LEN: usize = 64;

/// One table's contents, bucketed by prefix length.
///
/// # Cost
///
/// Exact lookup is one probe of the single bucket: `O(log n)` in a `BTreeMap`
/// with cache-friendly nodes, where n is a route table — thousands at most.
///
/// LPM is one probe per **populated prefix length**, longest first, so
/// `O(d log n)` where `d` is the number of distinct lengths installed (at most
/// 33 for IPv4, and typically two or three). It is *not* a scan over routes:
/// `buckets` is kept sorted by prefix descending on write, so the read path
/// neither derives nor sorts anything.
///
/// Neither path allocates. That is load-bearing rather than incidental — the
/// `ubpf` backend declares `AllocProfile::None` in `Backend::facts()`, and the
/// only heap traffic a frame could cause is here.
///
/// An earlier revision stored one flat `BTreeMap<(u8, Bytes), Bytes>` and
/// derived the prefix lengths per lookup, which made every packet cost a
/// `Vec` allocation plus an `O(n log n)` sort over the whole table. The
/// `backends` benchmark is what found it: `l3fwd` at 1000 routes cost 7.4 µs
/// per frame against 2.7 µs at one route. Both claims above were in this
/// comment at the time and neither was true, which is the argument for
/// measuring rather than asserting.
#[derive(Clone, Debug)]
pub struct Table {
    matching: Match,
    layout: Layout,
    /// Populated prefix lengths, **longest first**, each with the entries
    /// installed at that length keyed by their masked key image. An exact
    /// table has at most one bucket, at prefix 0.
    buckets: Vec<Bucket>,
    default: Option<Bytes>,
}

/// The entries sharing one prefix length.
#[derive(Clone, Debug)]
struct Bucket {
    prefix: u8,
    entries: BTreeMap<Bytes, Bytes>,
}

impl Table {
    /// An empty table. `default` is `Some` only for p4c's *defaultAction*
    /// map, which is an array of one and always answers; an entry map must
    /// return nothing on a miss, because that is the signal the generated code
    /// uses to go and consult the default map.
    ///
    /// # Panics
    /// If `layout.match_len` exceeds [`MAX_MATCH_LEN`]. A table is built from
    /// a compiled-in layout, so this is a build-time fact about the shipped
    /// programs, checked once here rather than per lookup.
    #[must_use]
    pub fn new(matching: Match, layout: Layout, default: Option<Bytes>) -> Self {
        assert!(
            layout.match_len <= MAX_MATCH_LEN,
            "match window {} exceeds MAX_MATCH_LEN {MAX_MATCH_LEN}",
            layout.match_len
        );
        Self {
            matching,
            layout,
            buckets: Vec::new(),
            default,
        }
    }

    /// This table's layout.
    #[must_use]
    pub const fn layout(&self) -> Layout {
        self.layout
    }

    /// Install or replace an entry. `prefix` is ignored for an exact table.
    ///
    /// `O(log n)` plus, for a prefix length not yet present, an insertion into
    /// `buckets` — `O(d)` to keep it sorted, with `d` at most 33.
    pub fn insert(&mut self, key: &[u8], prefix: u8, value: Bytes) {
        let (p, k) = self.canonical(key, prefix);
        // Descending by prefix, so the read path takes the first match.
        let at = self
            .buckets
            .binary_search_by(|b| p.cmp(&b.prefix))
            .unwrap_or_else(|at| {
                self.buckets.insert(
                    at,
                    Bucket {
                        prefix: p,
                        entries: BTreeMap::new(),
                    },
                );
                at
            });
        self.buckets[at].entries.insert(k, value);
    }

    /// Remove an entry, reporting whether one was there.
    ///
    /// A bucket emptied by the removal goes with it, so a prefix length that
    /// no longer has routes stops costing a probe.
    pub fn remove(&mut self, key: &[u8], prefix: u8) -> bool {
        let (p, k) = self.canonical(key, prefix);
        let Ok(at) = self.buckets.binary_search_by(|b| p.cmp(&b.prefix)) else {
            return false;
        };
        let gone = self.buckets[at].entries.remove(&k).is_some();
        if self.buckets[at].entries.is_empty() {
            self.buckets.remove(at);
        }
        gone
    }

    /// Replace the miss value.
    pub fn set_default(&mut self, value: Bytes) {
        self.default = Some(value);
    }

    /// Every entry as `(prefix, masked key, value)`, in a deterministic order:
    /// longest prefix first, then by key.
    pub fn iter(&self) -> impl Iterator<Item = (u8, &[u8], &[u8])> {
        self.buckets.iter().flat_map(|b| {
            b.entries
                .iter()
                .map(move |(k, v)| (b.prefix, k.as_slice(), v.as_slice()))
        })
    }

    /// Entries installed.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buckets.iter().map(|b| b.entries.len()).sum()
    }

    /// Whether no entry is installed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buckets.is_empty()
    }

    /// Forget every entry, reporting how many there were.
    pub fn clear(&mut self) -> usize {
        let n = self.len();
        self.buckets.clear();
        n
    }

    /// The value for `key`, if this table has one.
    ///
    /// `None` is meaningful rather than an absence to paper over: p4c's
    /// generated code tests the returned pointer against NULL and consults the
    /// table's default-action map when it is null. A table that always
    /// answered would make the miss path unreachable and `hit` always true.
    #[must_use]
    pub fn lookup(&self, key: &[u8]) -> Option<&[u8]> {
        let w = self.window(key);
        let found = match self.matching {
            // `BTreeMap<Vec<u8>, _>` probes by `&[u8]` through `Borrow`, so
            // the key image is never copied to ask a question about it.
            Match::Exact => self.buckets.first().and_then(|b| b.entries.get(w)),
            Match::Lpm => self.longest_prefix(w),
        };
        found.or(self.default.as_ref()).map(Vec::as_slice)
    }

    /// Longest-prefix search: probe each populated length, longest first.
    ///
    /// `buckets` is already in that order, so this is a walk, not a search for
    /// where to start. The mask goes into a stack buffer — `MAX_MATCH_LEN` is
    /// checked at construction, so the window always fits.
    fn longest_prefix(&self, key: &[u8]) -> Option<&Bytes> {
        let mut scratch = [0u8; MAX_MATCH_LEN];
        self.buckets.iter().find_map(|b| {
            let masked = mask_into(key, b.prefix, &mut scratch);
            b.entries.get(masked)
        })
    }

    /// The window of a key image that matching reads.
    fn window<'k>(&self, key: &'k [u8]) -> &'k [u8] {
        let end = (self.layout.match_at + self.layout.match_len).min(key.len());
        key.get(self.layout.match_at..end).unwrap_or(&[])
    }

    fn canonical(&self, key: &[u8], prefix: u8) -> (u8, Bytes) {
        let w = self.window(key);
        match self.matching {
            Match::Exact => (0, w.to_vec()),
            Match::Lpm => (prefix, mask(w, prefix)),
        }
    }
}

/// [`mask`] into a caller-owned buffer, returning the masked window.
///
/// The allocation-free form used by the read path; `mask` is the owning form
/// used on writes, where one allocation per control-plane call is free.
fn mask_into<'b>(key: &[u8], prefix: u8, out: &'b mut [u8; MAX_MATCH_LEN]) -> &'b [u8] {
    let n = key.len().min(MAX_MATCH_LEN);
    out[..n].copy_from_slice(&key[..n]);
    zero_below(&mut out[..n], prefix);
    &out[..n]
}

/// Zero every bit of `key` below the leading `prefix` bits.
///
/// The key image is little-endian, but a prefix is defined over the value's
/// *most significant* bits, so the masking walks the bytes in reverse.
#[must_use]
pub fn mask(key: &[u8], prefix: u8) -> Bytes {
    let mut out = key.to_vec();
    zero_below(&mut out, prefix);
    out
}

/// [`mask`], in place. The one definition of what a prefix means here; both
/// the owning and the borrowing form go through it, so the read and write
/// paths cannot disagree about which bits an entry is filed under.
fn zero_below(key: &mut [u8], prefix: u8) {
    let total = key.len() * 8;
    let keep = usize::from(prefix).min(total);
    for bit in keep..total {
        // Bit `bit` counted from the most significant end of the value.
        let from_lsb = total - 1 - bit;
        let byte = from_lsb / 8;
        let in_byte = from_lsb % 8;
        if let Some(b) = key.get_mut(byte) {
            *b &= !(1u8 << in_byte);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `struct pipe_mac_dst_value { enum action; union { struct { uint16_t
    /// port; } } }` — 4 bytes of discriminant, then the union, rounded to the
    /// struct's alignment of 4. The generated header is the authority; this
    /// records what it says.
    #[test]
    fn layouts_match_the_generated_header() {
        let header = include_str!("generated/l2fwd.h");
        assert!(
            header.contains("uint64_t hdr_ethernet_dst"),
            "l2fwd's key is no longer a single uint64"
        );
        assert!(
            header.contains("uint16_t port"),
            "l2fwd's forward parameter is no longer a uint16"
        );
        let l = Layout::scalar(8, 2);
        assert_eq!(l.key, 8);
        assert_eq!(l.value, 8, "4-byte action + 2-byte port, aligned to 4");
        assert_eq!(l.params_at, 4);
    }

    #[test]
    fn a_value_image_places_the_action_then_its_parameters() {
        let l = Layout::scalar(8, 2);
        let v = l.value(0, &7u16.to_le_bytes());
        assert_eq!(v, vec![0, 0, 0, 0, 7, 0, 0, 0]);
        let broadcast = l.value(1, &[]);
        assert_eq!(broadcast, vec![1, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn an_entry_map_returns_nothing_on_a_miss() {
        // The signal the generated code needs: NULL sends it to the default
        // map. A table that always answered would make that path unreachable.
        let l = Layout::scalar(8, 2);
        let t = Table::new(Match::Exact, l, None);
        assert_eq!(t.lookup(&[1; 8]), None);
    }

    #[test]
    fn an_exact_table_answers_the_default_on_a_miss() {
        let l = Layout::scalar(8, 2);
        let mut t = Table::new(Match::Exact, l, Some(l.value(1, &[])));
        assert_eq!(
            t.lookup(&[9; 8]).expect("default")[0],
            1,
            "miss takes the default"
        );
        t.insert(&[9; 8], 0, l.value(0, &3u16.to_le_bytes()));
        assert_eq!(t.lookup(&[9; 8]).expect("hit")[0], 0);
        assert_eq!(&t.lookup(&[9; 8]).expect("hit")[4..6], &3u16.to_le_bytes());
        assert!(t.remove(&[9; 8], 0));
        assert_eq!(
            t.lookup(&[9; 8]).expect("default")[0],
            1,
            "removal restores the default"
        );
    }

    #[test]
    fn masking_keeps_the_leading_bits_of_a_little_endian_key() {
        // 10.1.2.3 as a little-endian u32 image.
        let key = 0x0a01_0203u32.to_le_bytes().to_vec();
        assert_eq!(mask(&key, 32), key);
        assert_eq!(mask(&key, 24), 0x0a01_0200u32.to_le_bytes().to_vec());
        assert_eq!(mask(&key, 8), 0x0a00_0000u32.to_le_bytes().to_vec());
        assert_eq!(mask(&key, 0), vec![0, 0, 0, 0]);
    }

    #[test]
    fn lpm_prefers_the_longest_match() {
        let l = Layout::scalar(4, 2);
        let mut t = Table::new(Match::Lpm, l, Some(l.value(2, &[])));
        let broad = 0x0a00_0000u32.to_le_bytes();
        let narrow = 0x0a01_0000u32.to_le_bytes();
        t.insert(&broad, 8, l.value(0, &1u16.to_le_bytes()));
        t.insert(&narrow, 16, l.value(0, &2u16.to_le_bytes()));

        let key = 0x0a01_0203u32.to_le_bytes();
        assert_eq!(
            &t.lookup(&key).expect("hit")[4..6],
            &2u16.to_le_bytes(),
            "/16 wins"
        );

        let other = 0x0a02_0203u32.to_le_bytes();
        assert_eq!(
            &t.lookup(&other).expect("hit")[4..6],
            &1u16.to_le_bytes(),
            "/8 covers it"
        );

        let miss = 0x0b01_0203u32.to_le_bytes();
        assert_eq!(
            t.lookup(&miss).expect("default")[0],
            2,
            "outside every prefix: default"
        );
    }

    #[test]
    fn clearing_reports_what_it_removed() {
        let l = Layout::scalar(8, 2);
        let mut t = Table::new(Match::Exact, l, Some(l.value(1, &[])));
        for i in 0..5u8 {
            t.insert(&[i; 8], 0, l.value(0, &[0, 0]));
        }
        assert_eq!(t.len(), 5);
        assert_eq!(t.clear(), 5);
        assert!(t.is_empty());
    }
}
