//! Overlay wire format for up4 (spec S4).
//!
//! An up4 segment on the fabric is
//!
//! ```text
//! [ cluster IPv4/UDP (kernel) ][ 12-byte overlay header ][ inner Ethernet frame ]
//! ```
//!
//! This crate is the *pure core*: it owns the byte-level contract and nothing
//! else. No I/O, no allocation, no dependencies, no `unsafe`. Everything here
//! is total: [`decode`] is the single gate through which untrusted fabric bytes
//! become a trusted [`Hdr`], and its refusal set is closed ([`WireError`]).
//!
//! Cost: [`encode`] and [`decode`] are O(1), branch-light (encode is
//! branch-free), and touch exactly [`OVERLAY_HDR_LEN`] bytes.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod seq;

pub use seq::{REORDER_WINDOW, Seq, SeqEvent, SeqTracker};

use core::fmt;

/// Overlay header length in bytes (spec S4).
pub const OVERLAY_HDR_LEN: usize = 12;

/// Overlay version carried in the high nibble of byte 0.
pub const VERSION: u8 = 1;

/// Byte 0 as transmitted: version in the high nibble, flags (all zero in v1)
/// in the low nibble.
const VER_FLAGS: u8 = VERSION << 4;

/// Largest inner Ethernet frame on an IPv4 fabric with a 1500 B path MTU.
pub const INNER_MTU_V4: usize = 1460;

/// Largest inner Ethernet frame on an IPv6 fabric with a 1500 B path MTU.
pub const INNER_MTU_V6: usize = 1440;

/// Reserved vport id: frames whose egress port is this are punted to the
/// control channel (spec S5, S8.3). It is *not* a legal configured vport id.
pub const PUNT_VPORT: u16 = 65535;

/// Size of one fabric segment carrying an inner frame of `inner_mtu` bytes.
#[must_use]
pub const fn segment_len(inner_len: usize) -> usize {
    OVERLAY_HDR_LEN + inner_len
}

/// A decoded overlay header.
///
/// Version and flags are not fields: v1 has exactly one legal value for each,
/// so they are constants of the codec and illegal ones die in [`decode`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Hdr {
    /// Sender-side vport id. Tracing only; the receiver derives ingress from
    /// the source tuple (spec S6.2), never from this field.
    pub ingress_vport: u16,
    /// Per-(sender, vport) counter, monotonically increasing modulo 2^32.
    pub seq: Seq,
    /// Sender `CLOCK_MONOTONIC` microseconds, truncated to 32 bits.
    pub ts_us: u32,
}

/// The closed set of reasons a buffer is not a v1 overlay segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireError {
    /// Fewer than [`OVERLAY_HDR_LEN`] bytes were available.
    ShortBuffer,
    /// The version nibble was not [`VERSION`]; the observed value is carried.
    BadVersion(u8),
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShortBuffer => write!(
                f,
                "segment shorter than {OVERLAY_HDR_LEN}-byte overlay header"
            ),
            Self::BadVersion(v) => {
                write!(f, "unsupported overlay version {v} (expected {VERSION})")
            }
        }
    }
}

impl std::error::Error for WireError {}

/// Serialize `hdr` into a fixed 12-byte buffer.
///
/// Branch-free and allocation-free: one 12-byte store.
#[inline]
pub fn encode(hdr: &Hdr, out: &mut [u8; OVERLAY_HDR_LEN]) {
    let [v0, v1] = hdr.ingress_vport.to_be_bytes();
    let [s0, s1, s2, s3] = hdr.seq.get().to_be_bytes();
    let [t0, t1, t2, t3] = hdr.ts_us.to_be_bytes();
    *out = [VER_FLAGS, 0, v0, v1, s0, s1, s2, s3, t0, t1, t2, t3];
}

/// Parse the overlay header at the start of `buf`.
///
/// The only gate between fabric bytes and a trusted [`Hdr`]. The reserved byte
/// and the flag nibble are ignored by contract (spec S4: "must send 0;
/// receiver ignores"), so they are not part of the refusal set.
#[inline]
pub fn decode(buf: &[u8]) -> Result<Hdr, WireError> {
    let Some(b) = buf.first_chunk::<OVERLAY_HDR_LEN>() else {
        return Err(WireError::ShortBuffer);
    };
    let version = b[0] >> 4;
    if version != VERSION {
        return Err(WireError::BadVersion(version));
    }
    Ok(Hdr {
        ingress_vport: u16::from_be_bytes([b[2], b[3]]),
        seq: Seq::new(u32::from_be_bytes([b[4], b[5], b[6], b[7]])),
        ts_us: u32::from_be_bytes([b[8], b[9], b[10], b[11]]),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic xorshift64*, so the property test is reproducible and
    /// dependency-free (spec S2 closes the dependency list).
    struct XorShift(u64);

    impl XorShift {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }
    }

    #[test]
    fn round_trip_property() {
        let mut rng = XorShift(0x9e37_79b9_7f4a_7c15);
        let mut buf = [0u8; OVERLAY_HDR_LEN];
        for _ in 0..1_000_000 {
            let r = rng.next();
            let hdr = Hdr {
                ingress_vport: r as u16,
                seq: Seq::new((r >> 16) as u32),
                ts_us: (r >> 32) as u32,
            };
            encode(&hdr, &mut buf);
            assert_eq!(decode(&buf), Ok(hdr));
        }
    }

    #[test]
    fn encode_is_big_endian_at_documented_offsets() {
        let mut buf = [0xffu8; OVERLAY_HDR_LEN];
        encode(
            &Hdr {
                ingress_vport: 0x0102,
                seq: Seq::new(0x0304_0506),
                ts_us: 0x0708_090a,
            },
            &mut buf,
        );
        assert_eq!(
            buf,
            [
                0x10, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a
            ]
        );
    }

    #[test]
    fn rejects_short_buffer() {
        for len in 0..OVERLAY_HDR_LEN {
            let buf = vec![0x10; len];
            assert_eq!(decode(&buf), Err(WireError::ShortBuffer));
        }
    }

    #[test]
    fn rejects_wrong_version() {
        let mut buf = [0u8; OVERLAY_HDR_LEN];
        encode(&Hdr::default(), &mut buf);
        for version in (0u8..16).filter(|v| *v != VERSION) {
            buf[0] = version << 4;
            assert_eq!(decode(&buf), Err(WireError::BadVersion(version)));
        }
    }

    #[test]
    fn ignores_flags_and_reserved_byte() {
        let mut buf = [0u8; OVERLAY_HDR_LEN];
        let hdr = Hdr {
            ingress_vport: 7,
            seq: Seq::new(9),
            ts_us: 11,
        };
        encode(&hdr, &mut buf);
        buf[0] |= 0x0f;
        buf[1] = 0xff;
        assert_eq!(decode(&buf), Ok(hdr));
    }

    #[test]
    fn accepts_trailing_payload() {
        let mut buf = [0u8; OVERLAY_HDR_LEN + 64];
        let hdr = Hdr {
            ingress_vport: 3,
            seq: Seq::new(4),
            ts_us: 5,
        };
        let (head, _) = buf.split_at_mut(OVERLAY_HDR_LEN);
        encode(&hdr, head.try_into().expect("split at header length"));
        assert_eq!(decode(&buf), Ok(hdr));
    }
}
