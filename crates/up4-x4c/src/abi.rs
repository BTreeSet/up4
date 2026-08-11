//! The byte encoding x4c's generated table setters expect.
//!
//! `p4rs::Pipeline::add_table_entry` takes two opaque byte strings, so the
//! correspondence between up4's typed control plane and x4c's tables lives
//! entirely in this module. Every rule below is pinned by a test that would
//! also fail under the opposite convention; the encodings are *not* uniform,
//! and reading the upstream extractors is not enough to tell them apart.
//!
//! **Exact keys are least-significant byte first.** `extract_exact_key` reads
//! them with `BigUint::from_bytes_le`, so a MAC that appears on the wire as
//! `aa:bb:cc:dd:ee:ff` is supplied as `ff:ee:dd:cc:bb:aa`.
//!
//! **LPM keys are wire order, with the prefix length appended.**
//! `extract_lpm_key` dispatches on the buffer's total length and builds an
//! `IpAddr` from `bytes[0..4]` directly, so the address keeps its network
//! order and byte 4 carries the prefix length. Two key kinds, two orders, in
//! the same compiler.
//!
//! **Action parameters are least-significant byte first, packed in
//! declaration order** on byte boundaries, each occupying `ceil(bits/8)` bytes.
//!
//! Cost: every encoding is a fixed-size push into a `SmallBuf` sized for the
//! largest key up4 admits (an IPv4 prefix, 5 bytes) or the widest parameter
//! list (`forward(port, dmac)`, 8 bytes). No allocation.

use up4_engine::{KeyKind, TypedKey, TypedVal, ValKind};

/// The widest encoding either function produces. `forward(bit<16>, bit<48>)`
/// is 8 bytes; an IPv4 LPM key is 5. A fixed array keeps the control plane
/// allocation-free without a dependency.
pub const MAX_ENCODED: usize = 16;

/// A stack buffer for one encoded key or parameter list.
#[derive(Clone, Copy, Debug)]
pub struct Encoded {
    bytes: [u8; MAX_ENCODED],
    len: usize,
}

impl Encoded {
    const fn empty() -> Self {
        Self {
            bytes: [0; MAX_ENCODED],
            len: 0,
        }
    }

    /// Append `src` least-significant byte first.
    ///
    /// Panics only on a programming error; the capacity is checked against
    /// every schema this crate ships by `encodes_every_shipped_schema`.
    fn push_le(&mut self, src: &[u8]) {
        assert!(
            self.len + src.len() <= MAX_ENCODED,
            "MAX_ENCODED is too small for this schema"
        );
        for (i, b) in src.iter().rev().enumerate() {
            self.bytes[self.len + i] = *b;
        }
        self.len += src.len();
    }

    /// Append `src` in wire order.
    fn push_wire(&mut self, src: &[u8]) {
        assert!(self.len + src.len() <= MAX_ENCODED, "MAX_ENCODED too small");
        self.bytes[self.len..self.len + src.len()].copy_from_slice(src);
        self.len += src.len();
    }

    /// The encoded bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// The wire-order bytes of a value: how the field appears in a packet.
fn wire_bytes(v: TypedVal) -> ([u8; 8], usize) {
    let mut out = [0u8; 8];
    match v {
        TypedVal::U8(x) => {
            out[0] = x;
            (out, 1)
        }
        TypedVal::U16(x) => {
            out[..2].copy_from_slice(&x.to_be_bytes());
            (out, 2)
        }
        TypedVal::U32(x) => {
            out[..4].copy_from_slice(&x.to_be_bytes());
            (out, 4)
        }
        TypedVal::Mac(m) => {
            out[..6].copy_from_slice(&m.octets());
            (out, 6)
        }
        TypedVal::Ipv4(a) => {
            out[..4].copy_from_slice(&a.octets());
            (out, 4)
        }
    }
}

/// Encode a key for `add_table_entry` / `remove_table_entry`.
///
/// The two match kinds use *different* byte orders; see the module docs.
#[must_use]
pub fn encode_key(key: TypedKey) -> Encoded {
    let mut out = Encoded::empty();
    match key {
        TypedKey::Exact(v) => {
            let (b, n) = wire_bytes(v);
            out.push_le(&b[..n]);
        }
        TypedKey::Lpm { value, prefix_len } => {
            let (b, n) = wire_bytes(value);
            out.push_wire(&b[..n]);
            out.push_wire(&[prefix_len]);
        }
    }
    out
}

/// Encode an action's parameters, in declaration order.
#[must_use]
pub fn encode_params(params: &[TypedVal]) -> Encoded {
    params.iter().fold(Encoded::empty(), |mut acc, &p| {
        let (b, n) = wire_bytes(p);
        acc.push_le(&b[..n]);
        acc
    })
}

/// The width, in bytes, a value of this kind occupies in either encoding.
#[must_use]
pub const fn width(kind: ValKind) -> usize {
    match kind {
        ValKind::U8 => 1,
        ValKind::U16 => 2,
        ValKind::U32 | ValKind::Ipv4 => 4,
        ValKind::Mac => 6,
    }
}

/// The width of an encoded key of this kind: an LPM key carries its prefix
/// length in a trailing byte, which is what `extract_lpm_key` dispatches on.
#[must_use]
pub const fn key_width(kind: KeyKind) -> usize {
    match kind {
        KeyKind::Exact(v) => width(v),
        KeyKind::Lpm(v) => width(v) + 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use up4_engine::MacAddr;

    #[test]
    fn an_exact_key_is_least_significant_byte_first() {
        // Asymmetric on purpose: a palindrome would pass under either order.
        let mac = MacAddr::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        let e = encode_key(TypedKey::Exact(TypedVal::Mac(mac)));
        assert_eq!(e.as_slice(), &[0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa]);
        assert_ne!(
            e.as_slice(),
            &mac.octets(),
            "wire order must not round-trip"
        );
    }

    #[test]
    fn an_lpm_key_keeps_wire_order_and_appends_the_prefix_length() {
        let e = encode_key(TypedKey::Lpm {
            value: TypedVal::Ipv4(Ipv4Addr::new(10, 1, 2, 0)),
            prefix_len: 24,
        });
        // Address in network order, then the length, the shape
        // `extract_lpm_key` dispatches on by total length (5 = IPv4).
        assert_eq!(e.as_slice(), &[10, 1, 2, 0, 24]);
        assert_eq!(e.as_slice().len(), key_width(KeyKind::Lpm(ValKind::Ipv4)));
    }

    #[test]
    fn the_two_key_kinds_disagree_about_byte_order() {
        // Not a redundant test: it is the single most surprising fact in this
        // module, and a future refactor that "unifies" the two encodings would
        // pass both tests above only by accident.
        let addr = Ipv4Addr::new(1, 2, 3, 4);
        let exact = encode_key(TypedKey::Exact(TypedVal::Ipv4(addr)));
        let lpm = encode_key(TypedKey::Lpm {
            value: TypedVal::Ipv4(addr),
            prefix_len: 32,
        });
        assert_eq!(exact.as_slice(), &[4, 3, 2, 1]);
        assert_eq!(&lpm.as_slice()[..4], &[1, 2, 3, 4]);
    }

    #[test]
    fn parameters_pack_in_declaration_order_each_least_significant_first() {
        // `forward(bit<16> port, bit<48> dmac)` from l3fwd.
        let e = encode_params(&[
            TypedVal::U16(0x0102),
            TypedVal::Mac(MacAddr::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])),
        ]);
        assert_eq!(
            e.as_slice(),
            &[0x02, 0x01, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa]
        );
    }

    #[test]
    fn an_action_with_no_parameters_encodes_to_nothing() {
        assert!(encode_params(&[]).as_slice().is_empty());
    }

    #[test]
    fn encodes_every_shipped_schema() {
        // The buffer is fixed-size; this is what says it is big enough for
        // every table this crate can be asked about.
        for schemas in [
            up4_engine::programs::l2fwd::SCHEMAS,
            up4_engine::programs::l3fwd::SCHEMAS,
        ] {
            for t in schemas {
                assert!(key_width(t.key) <= MAX_ENCODED, "{}", t.name);
                for a in t.actions {
                    let total: usize = a.params.iter().map(|p| width(p.kind)).sum();
                    assert!(total <= MAX_ENCODED, "{}/{}", t.name, a.name);
                }
            }
        }
    }
}
