//! Header parsing and deparsing — the P4 `parser` and `deparser` blocks,
//! rendered in Rust.
//!
//! Two disciplines carry over from P4 and are worth stating:
//!
//! * **Validity is `Option`.** A header is either extracted or it is not;
//!   there is no "valid" bit to forget to check, because an absent header is an
//!   absent value. A truncated packet yields `None` and the program's control
//!   block decides what that means — it is never a panic and never a partially
//!   filled struct.
//! * **Views, not copies.** Each parsed header remembers its offset, so
//!   modification writes back into the frame in place.
//!
//! Cost: O(1), a fixed number of byte loads; no allocation.

use crate::value::MacAddr;
use std::net::Ipv4Addr;

/// Ethernet II header length.
pub const ETH_HDR_LEN: usize = 14;
/// Minimum legal IPv4 header length.
pub const IPV4_MIN_HDR_LEN: usize = 20;
/// Smallest Ethernet frame the corpus exercises (S10).
pub const MIN_FRAME_LEN: usize = 60;

/// EtherType for IPv4.
pub const ETHERTYPE_IPV4: u16 = 0x0800;
/// IP protocol number for TCP.
pub const IP_PROTO_TCP: u8 = 6;
/// IP protocol number for UDP.
pub const IP_PROTO_UDP: u8 = 17;

/// An extracted Ethernet header, always at offset 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ethernet {
    /// Destination address.
    pub dst: MacAddr,
    /// Source address.
    pub src: MacAddr,
    /// EtherType / length field.
    pub ethertype: u16,
}

impl Ethernet {
    /// Extract the header, or `None` if the frame is truncated.
    #[inline]
    #[must_use]
    pub fn parse(frame: &[u8]) -> Option<Self> {
        let b = frame.first_chunk::<ETH_HDR_LEN>()?;
        Some(Self {
            dst: MacAddr::new([b[0], b[1], b[2], b[3], b[4], b[5]]),
            src: MacAddr::new([b[6], b[7], b[8], b[9], b[10], b[11]]),
            ethertype: u16::from_be_bytes([b[12], b[13]]),
        })
    }

    /// Overwrite the destination address in place.
    #[inline]
    pub fn set_dst(frame: &mut [u8], mac: MacAddr) {
        if let Some(b) = frame.first_chunk_mut::<ETH_HDR_LEN>() {
            b[0..6].copy_from_slice(&mac.octets());
        }
    }

    /// Overwrite the source address in place.
    #[inline]
    pub fn set_src(frame: &mut [u8], mac: MacAddr) {
        if let Some(b) = frame.first_chunk_mut::<ETH_HDR_LEN>() {
            b[6..12].copy_from_slice(&mac.octets());
        }
    }
}

/// An extracted IPv4 header and where it sits in the frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv4 {
    /// Offset of the header within the frame.
    pub offset: usize,
    /// Header length in bytes (`ihl * 4`), at least [`IPV4_MIN_HDR_LEN`].
    pub hdr_len: usize,
    /// Total length field, as sent.
    pub total_len: u16,
    /// Time to live, as sent.
    pub ttl: u8,
    /// Transport protocol number.
    pub protocol: u8,
    /// Source address.
    pub src: Ipv4Addr,
    /// Destination address.
    pub dst: Ipv4Addr,
}

impl Ipv4 {
    /// Extract an IPv4 header at `offset`.
    ///
    /// Refuses a truncated header, a version other than 4, and an IHL that
    /// claims more bytes than the frame holds — so `offset + hdr_len` is a
    /// valid index range for every value this returns.
    #[must_use]
    pub fn parse(frame: &[u8], offset: usize) -> Option<Self> {
        let b = frame.get(offset..)?.first_chunk::<IPV4_MIN_HDR_LEN>()?;
        if b[0] >> 4 != 4 {
            return None;
        }
        let hdr_len = usize::from(b[0] & 0x0f) * 4;
        if hdr_len < IPV4_MIN_HDR_LEN || offset + hdr_len > frame.len() {
            return None;
        }
        Some(Self {
            offset,
            hdr_len,
            total_len: u16::from_be_bytes([b[2], b[3]]),
            ttl: b[8],
            protocol: b[9],
            src: Ipv4Addr::new(b[12], b[13], b[14], b[15]),
            dst: Ipv4Addr::new(b[16], b[17], b[18], b[19]),
        })
    }

    /// Offset of the transport header, given this header's extent.
    #[must_use]
    pub const fn payload_offset(&self) -> usize {
        self.offset + self.hdr_len
    }

    /// Write a new TTL in place.
    ///
    /// Total: [`Ipv4::parse`] proved the header is present, and this writes
    /// inside it.
    #[inline]
    pub fn set_ttl(&self, frame: &mut [u8], ttl: u8) {
        if let Some(byte) = frame.get_mut(self.offset + 8) {
            *byte = ttl;
        }
    }
}

/// Zero every inner checksum the frame carries (spec S1.5, S7.2).
///
/// up4 never computes or verifies an inner checksum; the outer UDP checksum
/// covers integrity on the fabric. Whenever a pipeline may have touched a
/// header, the containing checksum fields are zero-filled so that a stale
/// checksum is never mistaken for a valid one — and so the BMv2 differential
/// (S10) compares like with like after masking exactly these fields.
///
/// This is the *only* inner-packet modification the harness itself performs.
/// It is deliberately a sniff over canonical offsets rather than a parse: it
/// must be correct for frames whose pipeline did not extract these headers.
///
/// Cost: O(1), at most three 2-byte stores.
pub fn zero_inner_checksums(frame: &mut [u8]) {
    let Some(eth) = Ethernet::parse(frame) else {
        return;
    };
    if eth.ethertype != ETHERTYPE_IPV4 {
        return;
    }
    let Some(ip) = Ipv4::parse(frame, ETH_HDR_LEN) else {
        return;
    };
    zero_at(frame, ip.offset + 10);

    // The L4 checksum offset differs per protocol; anything else is left alone.
    let l4 = ip.payload_offset();
    match ip.protocol {
        IP_PROTO_TCP => zero_at(frame, l4 + 16),
        IP_PROTO_UDP => zero_at(frame, l4 + 6),
        _ => {}
    }
}

/// Zero the 16-bit field at `at`, if the frame is long enough to hold it.
#[inline]
fn zero_at(frame: &mut [u8], at: usize) {
    if let Some(field) = frame.get_mut(at..at + 2) {
        field.fill(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// eth(dst=aa..01, src=aa..02, ipv4) + ipv4(ttl=64, proto) + 8 payload bytes.
    fn frame(proto: u8) -> Vec<u8> {
        let mut f = vec![0u8; ETH_HDR_LEN + IPV4_MIN_HDR_LEN + 8];
        f[0..6].copy_from_slice(&[0xaa, 0, 0, 0, 0, 0x01]);
        f[6..12].copy_from_slice(&[0xaa, 0, 0, 0, 0, 0x02]);
        f[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        f[14] = 0x45;
        f[16..18].copy_from_slice(&28u16.to_be_bytes());
        f[22] = 64;
        f[23] = proto;
        f[24..26].copy_from_slice(&[0xde, 0xad]); // IPv4 header checksum
        f[26..30].copy_from_slice(&[10, 0, 0, 1]);
        f[30..34].copy_from_slice(&[10, 0, 1, 1]);
        f
    }

    #[test]
    fn parses_ethernet_and_ipv4() {
        let f = frame(IP_PROTO_UDP);
        let eth = Ethernet::parse(&f).expect("full header");
        assert_eq!(eth.ethertype, ETHERTYPE_IPV4);
        assert_eq!(eth.dst.to_string(), "aa:00:00:00:00:01");
        let ip = Ipv4::parse(&f, ETH_HDR_LEN).expect("full header");
        assert_eq!((ip.ttl, ip.protocol, ip.hdr_len), (64, IP_PROTO_UDP, 20));
        assert_eq!(ip.dst, Ipv4Addr::new(10, 0, 1, 1));
        assert_eq!(ip.payload_offset(), 34);
    }

    #[test]
    fn truncation_is_absence_not_a_panic() {
        let f = frame(IP_PROTO_UDP);
        for len in 0..ETH_HDR_LEN {
            assert_eq!(Ethernet::parse(&f[..len]), None, "len {len}");
        }
        for len in ETH_HDR_LEN..ETH_HDR_LEN + IPV4_MIN_HDR_LEN {
            assert_eq!(Ipv4::parse(&f[..len], ETH_HDR_LEN), None, "len {len}");
        }
    }

    #[test]
    fn rejects_bad_version_and_lying_ihl() {
        let mut f = frame(IP_PROTO_UDP);
        f[14] = 0x65; // version 6
        assert_eq!(Ipv4::parse(&f, ETH_HDR_LEN), None);
        f[14] = 0x43; // ihl 3 -> 12 bytes, below the minimum
        assert_eq!(Ipv4::parse(&f, ETH_HDR_LEN), None);
        f[14] = 0x4f; // ihl 15 -> 60 bytes, past the end of this frame
        assert_eq!(Ipv4::parse(&f, ETH_HDR_LEN), None);
    }

    #[test]
    fn ttl_and_macs_are_written_in_place() {
        let mut f = frame(IP_PROTO_UDP);
        let ip = Ipv4::parse(&f, ETH_HDR_LEN).expect("full header");
        ip.set_ttl(&mut f, 63);
        Ethernet::set_dst(&mut f, "bb:bb:bb:bb:bb:bb".parse().expect("literal"));
        Ethernet::set_src(&mut f, "cc:cc:cc:cc:cc:cc".parse().expect("literal"));
        let re = Ipv4::parse(&f, ETH_HDR_LEN).expect("still parses");
        assert_eq!(re.ttl, 63);
        let eth = Ethernet::parse(&f).expect("still parses");
        assert_eq!(eth.dst.to_string(), "bb:bb:bb:bb:bb:bb");
        assert_eq!(eth.src.to_string(), "cc:cc:cc:cc:cc:cc");
    }

    #[test]
    fn zeroes_ipv4_and_udp_checksums() {
        let mut f = frame(IP_PROTO_UDP);
        f[40..42].copy_from_slice(&[0xbe, 0xef]); // UDP checksum at l4 + 6
        zero_inner_checksums(&mut f);
        assert_eq!(&f[24..26], &[0, 0], "ipv4 header checksum");
        assert_eq!(&f[40..42], &[0, 0], "udp checksum");
    }

    #[test]
    fn zeroes_tcp_checksum() {
        let mut f = frame(IP_PROTO_TCP);
        f.resize(ETH_HDR_LEN + IPV4_MIN_HDR_LEN + 20, 0);
        f[50..52].copy_from_slice(&[0xbe, 0xef]); // TCP checksum at l4 + 16
        zero_inner_checksums(&mut f);
        assert_eq!(&f[50..52], &[0, 0]);
    }

    #[test]
    fn leaves_non_ip_and_truncated_frames_untouched() {
        let mut arp = vec![0xaa; ETH_HDR_LEN + 8];
        arp[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
        let before = arp.clone();
        zero_inner_checksums(&mut arp);
        assert_eq!(arp, before);

        let mut short = frame(IP_PROTO_UDP);
        short.truncate(ETH_HDR_LEN + 4);
        let before = short.clone();
        zero_inner_checksums(&mut short);
        assert_eq!(short, before, "a truncated IPv4 header is not zeroed blind");
    }

    #[test]
    fn truncated_l4_does_not_reach_past_the_frame() {
        let mut f = frame(IP_PROTO_TCP); // 8 payload bytes; TCP checksum is at +16
        zero_inner_checksums(&mut f);
        assert_eq!(&f[24..26], &[0, 0], "ipv4 checksum still zeroed");
        assert_eq!(f.len(), ETH_HDR_LEN + IPV4_MIN_HDR_LEN + 8);
    }
}
