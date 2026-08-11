//! Synthetic inner frames (spec S11.2).
//!
//! One template, built once, with the per-flow fields patched in place. The
//! frames are real Ethernet/IPv4/UDP so that a real P4 pipeline parses them;
//! a generator that emits noise would exercise the harness and nothing else.

use std::net::Ipv4Addr;
use up4_engine::{
    MacAddr,
    headers::{ETH_HDR_LEN, ETHERTYPE_IPV4, IP_PROTO_UDP, IPV4_MIN_HDR_LEN, MIN_FRAME_LEN},
};

/// Bytes of Ethernet + IPv4 + UDP header, the smallest frame this builds.
pub const MIN_TEMPLATE_LEN: usize = ETH_HDR_LEN + IPV4_MIN_HDR_LEN + UDP_HDR_LEN;

/// UDP header length.
pub const UDP_HDR_LEN: usize = 8;

/// What the generator puts in each frame.
#[derive(Clone, Copy, Debug)]
pub struct FrameSpec {
    /// Source MAC.
    pub src_mac: MacAddr,
    /// Destination MAC: for `l2fwd`, the key the switch matches on.
    pub dst_mac: MacAddr,
    /// Source IPv4 address; flows vary its low octet.
    pub src_ip: Ipv4Addr,
    /// Destination IPv4 address: for `l3fwd`, the route being exercised.
    pub dst_ip: Ipv4Addr,
    /// UDP source port; flows vary it.
    pub src_port: u16,
    /// UDP destination port.
    pub dst_port: u16,
    /// Total frame length, at least [`MIN_TEMPLATE_LEN`].
    pub len: usize,
}

impl Default for FrameSpec {
    fn default() -> Self {
        Self {
            src_mac: MacAddr::new([0x02, 0, 0, 0, 0, 1]),
            dst_mac: MacAddr::new([0x02, 0, 0, 0, 0, 2]),
            src_ip: Ipv4Addr::new(10, 0, 1, 1),
            dst_ip: Ipv4Addr::new(10, 0, 2, 1),
            src_port: 4000,
            dst_port: 4001,
            len: 1460,
        }
    }
}

/// A prebuilt frame whose per-flow fields can be rewritten without rebuilding.
#[derive(Clone, Debug)]
pub struct FrameTemplate {
    bytes: Vec<u8>,
    spec: FrameSpec,
}

impl FrameTemplate {
    /// Build the template. The requested length is raised to the minimum a
    /// well-formed UDP-over-IPv4 frame needs, and to Ethernet's 60 B floor.
    #[must_use]
    pub fn new(spec: FrameSpec) -> Self {
        let len = spec.len.max(MIN_TEMPLATE_LEN).max(MIN_FRAME_LEN);
        let mut bytes = vec![0u8; len];

        bytes[0..6].copy_from_slice(&spec.dst_mac.octets());
        bytes[6..12].copy_from_slice(&spec.src_mac.octets());
        bytes[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());

        let ip = ETH_HDR_LEN;
        let ip_total = len - ETH_HDR_LEN;
        bytes[ip] = 0x45;
        bytes[ip + 2..ip + 4].copy_from_slice(&(ip_total as u16).to_be_bytes());
        bytes[ip + 8] = 64; // TTL
        bytes[ip + 9] = IP_PROTO_UDP;
        // Checksums are zero by construction: up4 never verifies an inner
        // checksum and zero-fills on rewrite (spec S1.5).
        bytes[ip + 12..ip + 16].copy_from_slice(&spec.src_ip.octets());
        bytes[ip + 16..ip + 20].copy_from_slice(&spec.dst_ip.octets());

        let udp = ip + IPV4_MIN_HDR_LEN;
        bytes[udp..udp + 2].copy_from_slice(&spec.src_port.to_be_bytes());
        bytes[udp + 2..udp + 4].copy_from_slice(&spec.dst_port.to_be_bytes());
        bytes[udp + 4..udp + 6]
            .copy_from_slice(&((ip_total - IPV4_MIN_HDR_LEN) as u16).to_be_bytes());

        // A recognizable payload, so a corrupted frame is obvious in a capture.
        for (i, byte) in bytes[udp + UDP_HDR_LEN..].iter_mut().enumerate() {
            *byte = (i % 251) as u8;
        }
        Self {
            bytes,
            spec: FrameSpec { len, ..spec },
        }
    }

    /// The template's length after rounding.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Always false; a template always has headers.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        false
    }

    /// The spec as built, with the effective length.
    #[must_use]
    pub const fn spec(&self) -> FrameSpec {
        self.spec
    }

    /// The frame for flow `flow`, of `flows` total.
    ///
    /// Varying the source address and port is what gives the fabric something
    /// to hash on, which is how GRO coalescing gets exercised (or defeated,
    /// with one flow per frame).
    #[must_use]
    pub fn for_flow(&mut self, flow: u32, flows: u32) -> &[u8] {
        if flows > 1 {
            let ip = ETH_HDR_LEN;
            let udp = ip + IPV4_MIN_HDR_LEN;
            let octets = self.spec.src_ip.octets();
            let varied = Ipv4Addr::new(
                octets[0],
                octets[1],
                octets[2].wrapping_add((flow >> 8) as u8),
                octets[3].wrapping_add(flow as u8),
            );
            self.bytes[ip + 12..ip + 16].copy_from_slice(&varied.octets());
            self.bytes[udp..udp + 2]
                .copy_from_slice(&self.spec.src_port.wrapping_add(flow as u16).to_be_bytes());
        }
        &self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use up4_engine::headers::{Ethernet, Ipv4};

    #[test]
    fn a_template_is_a_frame_a_pipeline_can_parse() {
        let t = FrameTemplate::new(FrameSpec::default());
        let eth = Ethernet::parse(&t.bytes).expect("ethernet");
        assert_eq!(eth.ethertype, ETHERTYPE_IPV4);
        assert_eq!(eth.dst, MacAddr::new([0x02, 0, 0, 0, 0, 2]));
        let ip = Ipv4::parse(&t.bytes, ETH_HDR_LEN).expect("ipv4");
        assert_eq!(ip.ttl, 64);
        assert_eq!(ip.protocol, IP_PROTO_UDP);
        assert_eq!(ip.dst, Ipv4Addr::new(10, 0, 2, 1));
        assert_eq!(usize::from(ip.total_len), t.len() - ETH_HDR_LEN);
    }

    #[test]
    fn short_requests_are_raised_to_a_legal_frame() {
        let t = FrameTemplate::new(FrameSpec {
            len: 1,
            ..FrameSpec::default()
        });
        assert_eq!(t.len(), MIN_FRAME_LEN);
        assert!(Ipv4::parse(&t.bytes, ETH_HDR_LEN).is_some());
        assert_eq!(
            t.spec().len,
            MIN_FRAME_LEN,
            "the spec reports what was built"
        );
    }

    #[test]
    fn flows_vary_the_source_and_leave_the_destination_alone() {
        let mut t = FrameTemplate::new(FrameSpec::default());
        let first = t.for_flow(0, 4).to_vec();
        let second = t.for_flow(1, 4).to_vec();
        assert_ne!(first, second);
        let a = Ipv4::parse(&first, ETH_HDR_LEN).expect("ipv4");
        let b = Ipv4::parse(&second, ETH_HDR_LEN).expect("ipv4");
        assert_ne!(a.src, b.src);
        assert_eq!(a.dst, b.dst, "the route under test does not move");
    }

    #[test]
    fn a_single_flow_is_byte_identical_every_time() {
        let mut t = FrameTemplate::new(FrameSpec::default());
        assert_eq!(t.for_flow(0, 1).to_vec(), t.for_flow(7, 1).to_vec());
    }
}
