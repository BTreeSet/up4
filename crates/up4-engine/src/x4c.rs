//! The x4c seam (spec S7.2, S7.3).
//!
//! up4 v1 as specified compiles each `p4/programs/*/*.softnpu.p4` with a pinned `x4c`
//! and adapts the generated `Pipeline` onto [`crate::Engine`]. This build does
//! not run x4c (see `docs/deviations.md`); the compiled-in programs are direct
//! renderings of the same P4 sources onto the same two contracts. This module
//! is what keeps that a *seam* rather than a fork:
//!
//! * [`abi`] pins the byte-level key/parameter encoding the adapter must speak,
//!   with the fixed-vector tests spec S13.1 asks for. When generated code
//!   arrives, these tests are what tell us whether it agrees.
//! * [`refuse_reason`] is the compile-time refusal of programs up4 cannot honour
//!   (spec S7.2), already applied to the checked-in sources by this crate's
//!   tests, and ready to be called from `build.rs`.
//!
//! ## What the adapter will do
//!
//! * Ingress metadata from [`crate::FrameCtx::ingress_vport`] and `rx_ts_us`.
//! * Egress metadata to a [`crate::Verdict`]: `drop` → `Drop`, `broadcast` →
//!   `Broadcast`, egress port [`up4_wire::PUNT_VPORT`] → `Punt`, otherwise
//!   `Forward(port)`.
//! * Inner checksum zero-fill after any run that may have modified a header
//!   ([`crate::headers::zero_inner_checksums`]), the harness's only
//!   inner-packet touch (spec S1.5).
//!
//! ## The endianness contradiction
//!
//! Upstream x4c documentation contradicts itself: its endianness section gives
//! the rules pinned in [`abi`] (exact and range keys little-endian, LPM keys in
//! wire order, action parameters little-endian) while its control-plane
//! walkthrough says everything is big-endian. Spec S7.3 settles it: the pinned
//! revision's generated code is the authority, and these vectors are to be
//! *re-pinned to what it actually does*, not "fixed" to match a document.

/// The byte-level control-plane ABI (spec S7.3).
pub mod abi {
    use crate::value::TypedVal;

    /// Encode an exact-match key field: little-endian.
    #[must_use]
    pub fn exact_key(v: TypedVal) -> Vec<u8> {
        let mut bytes = wire_bytes(v);
        bytes.reverse();
        bytes
    }

    /// Encode an LPM key field: wire (big-endian) byte order.
    #[must_use]
    pub fn lpm_key(v: TypedVal) -> Vec<u8> {
        wire_bytes(v)
    }

    /// Encode an action parameter: little-endian.
    #[must_use]
    pub fn action_param(v: TypedVal) -> Vec<u8> {
        exact_key(v)
    }

    /// A value's big-endian (wire) representation, which is also the natural
    /// order for the address types.
    fn wire_bytes(v: TypedVal) -> Vec<u8> {
        match v {
            TypedVal::U8(x) => x.to_be_bytes().to_vec(),
            TypedVal::U16(x) => x.to_be_bytes().to_vec(),
            TypedVal::U32(x) => x.to_be_bytes().to_vec(),
            TypedVal::Mac(x) => x.octets().to_vec(),
            TypedVal::Ipv4(x) => x.octets().to_vec(),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::value::{MacAddr, ValKind};

        /// Fixed byte vectors (spec S13.1). These are the contract; changing
        /// one means the generated code changed, not that the test was wrong.
        #[test]
        fn exact_keys_are_little_endian() {
            assert_eq!(exact_key(TypedVal::U16(0x0102)), vec![0x02, 0x01]);
            assert_eq!(
                exact_key(TypedVal::U32(0x0102_0304)),
                vec![0x04, 0x03, 0x02, 0x01]
            );
            assert_eq!(
                exact_key(TypedVal::Mac(MacAddr::new([1, 2, 3, 4, 5, 6]))),
                vec![6, 5, 4, 3, 2, 1]
            );
            assert_eq!(
                exact_key(TypedVal::U8(0xab)),
                vec![0xab],
                "one byte has no order"
            );
        }

        #[test]
        fn lpm_keys_are_wire_order() {
            let addr = TypedVal::parse(ValKind::Ipv4, "10.0.0.1").expect("literal");
            assert_eq!(lpm_key(addr), vec![10, 0, 0, 1]);
            assert_eq!(
                exact_key(addr),
                vec![1, 0, 0, 10],
                "the same value, the other way"
            );
        }

        #[test]
        fn action_parameters_follow_the_exact_key_rule() {
            assert_eq!(action_param(TypedVal::U16(1)), vec![1, 0]);
        }
    }
}

/// Reject P4 sources that ask for hardware up4 does not model (spec S7.2).
///
/// A substring denylist is the whole mechanism, deliberately: build-time
/// refusal must not require a P4 parser. Returns the message to fail with, or
/// `None` if the program is loadable.
#[must_use]
pub fn refuse_reason(source: &str) -> Option<&'static str> {
    /// Identifiers that imply a traffic manager or metering hardware.
    const DENIED: [(&str, &str); 5] = [
        ("queue_depth", "no traffic manager in up4 v1"),
        ("enq_qdepth", "no traffic manager in up4 v1"),
        ("deq_qdepth", "no traffic manager in up4 v1"),
        ("deq_timedelta", "no traffic manager in up4 v1"),
        ("meter", "no meters in up4 v1"),
    ];
    let code = strip_comments(source);
    DENIED
        .iter()
        .find(|(needle, _)| code.contains(needle))
        .map(|(_, why)| *why)
}

/// Drop `//` and `/* */` comments, so prose about queueing does not fail a
/// build and a comment cannot hide a denied identifier.
fn strip_comments(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    let mut rest = source;
    while let Some(start) = rest.find("//").into_iter().chain(rest.find("/*")).min() {
        out.push_str(&rest[..start]);
        let (opener, closer) = if rest[start..].starts_with("//") {
            ("//", "\n")
        } else {
            ("/*", "*/")
        };
        rest = match rest[start + opener.len()..].find(closer) {
            Some(end) => &rest[start + opener.len() + end + closer.len()..],
            None => "",
        };
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_traffic_manager_and_meter_intrinsics() {
        assert_eq!(
            refuse_reason("if (standard_metadata.enq_qdepth > 4) { drop(); }"),
            Some("no traffic manager in up4 v1")
        );
        assert_eq!(
            refuse_reason("meter(m, idx, res);"),
            Some("no meters in up4 v1")
        );
    }

    #[test]
    fn accepts_a_program_that_only_mentions_them_in_comments() {
        assert_eq!(refuse_reason("// no queue_depth here\naction a() {}"), None);
        assert_eq!(
            refuse_reason("/* meter\n is out of scope */\naction a() {}"),
            None
        );
        assert_eq!(refuse_reason("action a() {} // unterminated"), None);
    }

    /// The refusal that spec S7.2 asks for, applied to the sources we ship.
    #[test]
    fn every_checked_in_program_is_loadable() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../p4/programs");
        let mut seen = 0;
        for entry in std::fs::read_dir(&root).expect("p4/programs exists") {
            let dir = entry.expect("readable entry").path();
            let name = dir
                .file_name()
                .and_then(|n| n.to_str())
                .expect("utf-8 name")
                .to_owned();
            let src_path = dir.join(format!("{name}.softnpu.p4"));
            let src = std::fs::read_to_string(&src_path)
                .unwrap_or_else(|e| panic!("{} unreadable: {e}", src_path.display()));
            assert_eq!(
                refuse_reason(&src),
                None,
                "{name}.softnpu.p4 would be refused at build time"
            );
            seen += 1;
        }
        assert_eq!(seen, 2, "l2fwd and l3fwd each have a .p4 source of record");
    }
}
