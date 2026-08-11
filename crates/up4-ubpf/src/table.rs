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

/// One table's contents.
///
/// Cost: exact lookup is one `BTreeMap` probe, O(log n) with cache-friendly
/// nodes — n here is a route table, thousands at most, and the map is rebuilt
/// on write rather than read, so the read path never allocates. LPM is a scan
/// over distinct prefix lengths, longest first, so it costs one probe per
/// populated length rather than one per route (the same bound the `native`
/// backend's LPM achieves, for the same reason).
#[derive(Clone, Debug)]
pub struct Table {
    matching: Match,
    layout: Layout,
    /// Exact: key image → value image. LPM: (prefix_len, masked key) → value.
    entries: BTreeMap<(u8, Bytes), Bytes>,
    default: Option<Bytes>,
}

impl Table {
    /// An empty table. `default` is `Some` only for p4c's *defaultAction*
    /// map, which is an array of one and always answers; an entry map must
    /// return nothing on a miss, because that is the signal the generated code
    /// uses to go and consult the default map.
    #[must_use]
    pub fn new(matching: Match, layout: Layout, default: Option<Bytes>) -> Self {
        Self {
            matching,
            layout,
            entries: BTreeMap::new(),
            default,
        }
    }

    /// This table's layout.
    #[must_use]
    pub const fn layout(&self) -> Layout {
        self.layout
    }

    /// Install or replace an entry. `prefix` is ignored for an exact table.
    pub fn insert(&mut self, key: &[u8], prefix: u8, value: Bytes) {
        let (p, k) = self.canonical(key, prefix);
        self.entries.insert((p, k), value);
    }

    /// Remove an entry, reporting whether one was there.
    pub fn remove(&mut self, key: &[u8], prefix: u8) -> bool {
        let (p, k) = self.canonical(key, prefix);
        self.entries.remove(&(p, k)).is_some()
    }

    /// Replace the miss value.
    pub fn set_default(&mut self, value: Bytes) {
        self.default = Some(value);
    }

    /// Every entry, in a deterministic order.
    pub fn iter(&self) -> impl Iterator<Item = (&(u8, Bytes), &Bytes)> {
        self.entries.iter()
    }

    /// Entries installed.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no entry is installed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Forget every entry, reporting how many there were.
    pub fn clear(&mut self) -> usize {
        let n = self.entries.len();
        self.entries.clear();
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
        let found = match self.matching {
            Match::Exact => self.entries.get(&(0, key.to_vec())),
            Match::Lpm => self.longest_prefix(key),
        };
        found.or(self.default.as_ref()).map(Vec::as_slice)
    }

    /// Longest-prefix search: try each populated length, longest first.
    fn longest_prefix(&self, key: &[u8]) -> Option<&Bytes> {
        let mut lengths: Vec<u8> = self.entries.keys().map(|(p, _)| *p).collect();
        lengths.sort_unstable_by(|a, b| b.cmp(a));
        lengths.dedup();
        lengths.into_iter().find_map(|p| {
            let masked = mask(key, p);
            self.entries.get(&(p, masked))
        })
    }

    fn canonical(&self, key: &[u8], prefix: u8) -> (u8, Bytes) {
        match self.matching {
            Match::Exact => (0, key.to_vec()),
            Match::Lpm => (prefix, mask(key, prefix)),
        }
    }
}

/// Zero every bit of `key` below the leading `prefix` bits.
///
/// The key image is little-endian, but a prefix is defined over the value's
/// *most significant* bits, so the masking walks the bytes in reverse.
#[must_use]
pub fn mask(key: &[u8], prefix: u8) -> Bytes {
    let mut out = key.to_vec();
    let total = out.len() * 8;
    let keep = usize::from(prefix).min(total);
    for bit in keep..total {
        // Bit `bit` counted from the most significant end of the value.
        let from_lsb = total - 1 - bit;
        let byte = from_lsb / 8;
        let in_byte = from_lsb % 8;
        if let Some(b) = out.get_mut(byte) {
            *b &= !(1u8 << in_byte);
        }
    }
    out
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
