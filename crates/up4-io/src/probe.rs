//! Capability probe (spec S11.1).
//!
//! up4 never *raises* a system limit; it asks, records what it was given, and
//! says so (spec S1.1, P3). The probe is that recording, emitted as one JSON
//! object: by `up4d` as its startup banner and by the `probe` tool standalone.
//!
//! Everything here is best-effort by construction: an unreadable file or an
//! unsupported socket option is data (`None`, `false`) and never an error, so a
//! probe on an unfamiliar kernel still produces a complete document.

use crate::socket::{FabricSocket, WANT_BUF_BYTES};
use serde::Serialize;
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
};

/// `UDP_SEGMENT`: the GSO socket option. Not re-exported by `libc` on every
/// target, and its value is kernel ABI.
const UDP_SEGMENT: libc::c_int = 103;
/// `UDP_GRO`: the receive-offload socket option.
const UDP_GRO: libc::c_int = 104;

/// The MTU up4's inner MTU constants assume (spec S17).
pub const ASSUMED_MTU: u32 = 1500;

/// Everything the probe learned.
#[derive(Clone, Debug, Serialize)]
pub struct Probe {
    /// `uname -r`.
    pub kernel: String,
    /// `uname -m`.
    pub arch: String,
    /// Buffer size requested for each direction.
    pub sockbuf_requested: usize,
    /// Buffer size the kernel granted for receive.
    pub rcvbuf_granted: usize,
    /// Buffer size the kernel granted for send.
    pub sndbuf_granted: usize,
    /// Whether `setsockopt(UDP_GRO)` succeeded.
    pub udp_gro: bool,
    /// Whether `setsockopt(UDP_SEGMENT)` succeeded.
    pub udp_segment: bool,
    /// Segments quinn-udp will coalesce per read.
    pub gro_segments: usize,
    /// Segments quinn-udp will emit per write.
    pub max_gso_segments: usize,
    /// Whether the socket may fragment.
    pub may_fragment: bool,
    /// `/proc/sys/kernel/io_uring_disabled`, if readable.
    pub io_uring_disabled: Option<String>,
    /// CPUs this process may run on, from the cgroup cpuset when readable.
    pub cpus_available: usize,
    /// The raw cpuset string, when one was found.
    pub cpuset: Option<String>,
    /// Route MTU to the peer the caller asked about.
    pub peer_mtu: Option<PeerMtu>,
    /// Assumptions from spec S17 that this host contradicts.
    pub warnings: Vec<String>,
}

/// The egress interface and MTU for a peer address.
#[derive(Clone, Debug, Serialize)]
pub struct PeerMtu {
    /// The peer that was asked about.
    pub peer: IpAddr,
    /// Interface the route table selects.
    pub interface: String,
    /// That interface's MTU, if readable.
    pub mtu: Option<u32>,
}

/// Run the probe. `peer` selects the route whose MTU is reported.
///
/// Cost: a handful of file reads and one throwaway socket; startup only.
#[must_use]
pub fn probe(peer: Option<IpAddr>) -> Probe {
    let (kernel, arch) = uname();
    let mut warnings = Vec::new();

    let sock = FabricSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), false).ok();
    let caps = sock.as_ref().map(FabricSocket::caps);
    let cpuset = read_trimmed("/sys/fs/cgroup/cpuset.cpus.effective")
        .or_else(|| read_trimmed("/sys/fs/cgroup/cpuset/cpuset.effective_cpus"));
    let cpus_available = cpuset
        .as_deref()
        .map(count_cpuset)
        .filter(|n| *n > 0)
        .or_else(|| {
            std::thread::available_parallelism()
                .ok()
                .map(std::num::NonZero::get)
        })
        .unwrap_or(1);

    let peer_mtu = peer.map(peer_mtu);
    if let Some(p) = &peer_mtu
        && let Some(mtu) = p.mtu
        && mtu < ASSUMED_MTU
    {
        warnings.push(format!(
            "route to {} via {} has MTU {mtu} < {ASSUMED_MTU}; inner MTU must be recomputed \
             from it (spec S17)",
            p.peer, p.interface
        ));
    }
    if caps.is_some_and(|c| !c.gro()) {
        warnings
            .push("UDP GRO unavailable; receive falls back to one datagram per read".to_owned());
    }
    if caps.is_some_and(|c| !c.gso()) {
        warnings
            .push("UDP GSO unavailable; transmit falls back to one datagram per write".to_owned());
    }
    if caps.is_some_and(|c| c.rcvbuf < WANT_BUF_BYTES) {
        warnings.push(format!(
            "SO_RCVBUF granted {} of {WANT_BUF_BYTES} requested; raising net.core.rmem_max is \
             out of scope for an unprivileged process (spec S1.1)",
            caps.map_or(0, |c| c.rcvbuf)
        ));
    }

    Probe {
        kernel,
        arch,
        sockbuf_requested: WANT_BUF_BYTES,
        rcvbuf_granted: caps.map_or(0, |c| c.rcvbuf),
        sndbuf_granted: caps.map_or(0, |c| c.sndbuf),
        udp_gro: setsockopt_works(UDP_GRO, 1),
        udp_segment: setsockopt_works(UDP_SEGMENT, 1472),
        gro_segments: caps.map_or(1, |c| c.gro_segments),
        max_gso_segments: caps.map_or(1, |c| c.max_gso_segments),
        may_fragment: caps.is_some_and(|c| c.may_fragment),
        io_uring_disabled: read_trimmed("/proc/sys/kernel/io_uring_disabled"),
        cpus_available,
        cpuset,
        peer_mtu,
        warnings,
    }
}

/// Kernel release and machine, from `uname(2)`.
fn uname() -> (String, String) {
    let mut buf = std::mem::MaybeUninit::<libc::utsname>::uninit();
    // SAFETY: `uname` fills the `utsname` it is given and touches nothing else.
    // We read the buffer only when it reports success, so the fields are
    // initialized NUL-terminated C strings.
    let filled = unsafe { libc::uname(buf.as_mut_ptr()) == 0 };
    if !filled {
        return ("unknown".to_owned(), "unknown".to_owned());
    }
    // SAFETY: `uname` returned success, so every field is initialized.
    let u = unsafe { buf.assume_init() };
    (c_str(&u.release), c_str(&u.machine))
}

/// A NUL-terminated fixed-size C string field as a `String`.
fn c_str(field: &[libc::c_char]) -> String {
    // `c_char` is `i8` on x86_64 and `u8` on aarch64, so exactly one of the two
    // targets sees this cast as redundant. Keep it for the other one.
    #[allow(clippy::unnecessary_cast)]
    let bytes: Vec<u8> = field
        .iter()
        .take_while(|c| **c != 0)
        .map(|c| *c as u8)
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Whether a UDP socket accepts `option` set to `value`.
fn setsockopt_works(option: libc::c_int, value: libc::c_int) -> bool {
    let Ok(sock) = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)) else {
        return false;
    };
    use std::os::fd::AsRawFd;
    // SAFETY: `sock` owns a live fd for the duration of the call; the pointer
    // and length describe a `c_int` local, which is what SOL_UDP's integer
    // options expect. The return value is checked and nothing is retained.
    let rc = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::SOL_UDP,
            option,
            (&raw const value).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    rc == 0
}

/// Route lookup for `peer`, longest matching prefix in `/proc/net/route`.
fn peer_mtu(peer: IpAddr) -> PeerMtu {
    let interface = match peer {
        IpAddr::V4(v4) => route_interface(&read_or_empty("/proc/net/route"), v4),
        // IPv6 routes live in a different file with a different format; up4's
        // fabric default is IPv4 and the probe says so rather than guessing.
        IpAddr::V6(_) => None,
    };
    let mtu = interface
        .as_deref()
        .and_then(|i| read_trimmed(format!("/sys/class/net/{i}/mtu")))
        .and_then(|s| s.parse().ok());
    PeerMtu {
        peer,
        interface: interface.unwrap_or_else(|| "unknown".to_owned()),
        mtu,
    }
}

/// The interface `/proc/net/route` selects for `dest`.
///
/// Cost: O(routes); the table is tens of entries and this runs once.
fn route_interface(table: &str, dest: Ipv4Addr) -> Option<String> {
    let target = u32::from_be_bytes(dest.octets());
    table
        .lines()
        .skip(1) // header
        .filter_map(|line| {
            let mut f = line.split_whitespace();
            let iface = f.next()?;
            let destination = hex_addr(f.next()?)?;
            let mask = hex_addr(f.nth(5)?)?; // flags, refcnt, use, metric, then mask
            (target & mask == destination).then(|| (mask.count_ones(), iface.to_owned()))
        })
        .max_by_key(|(bits, _)| *bits)
        .map(|(_, iface)| iface)
}

/// A `/proc/net/route` hex field as a host-order address value.
///
/// The kernel prints the network-order word in the host's byte order, so on a
/// little-endian machine the digits arrive reversed.
fn hex_addr(field: &str) -> Option<u32> {
    let raw = u32::from_str_radix(field, 16).ok()?;
    Some(if cfg!(target_endian = "little") {
        raw.swap_bytes()
    } else {
        raw
    })
}

/// Count the CPUs in a cpuset list such as `0-3,8`.
fn count_cpuset(spec: &str) -> usize {
    spec.split(',')
        .filter_map(|part| match part.split_once('-') {
            None => part.trim().parse::<usize>().ok().map(|_| 1),
            Some((lo, hi)) => {
                let (lo, hi) = (
                    lo.trim().parse::<usize>().ok()?,
                    hi.trim().parse::<usize>().ok()?,
                );
                hi.checked_sub(lo).map(|n| n + 1)
            }
        })
        .sum()
}

fn read_trimmed(path: impl AsRef<Path>) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

fn read_or_empty(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_probe_on_this_host_is_complete_and_serializes() {
        let p = probe(Some(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(!p.kernel.is_empty() && p.kernel != "unknown", "{p:?}");
        assert!(!p.arch.is_empty());
        assert!(p.cpus_available >= 1);
        assert!(
            p.rcvbuf_granted > 0,
            "a loopback socket reports a receive buffer"
        );
        assert_eq!(p.sockbuf_requested, WANT_BUF_BYTES);
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&p).expect("serializes")).expect("valid");
        assert!(
            json.get("warnings")
                .is_some_and(serde_json::Value::is_array)
        );
    }

    #[test]
    fn loopback_route_resolves_to_an_interface() {
        let p = peer_mtu(IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(p.peer, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert!(p.mtu.is_none() || p.mtu.is_some_and(|m| m >= 1500), "{p:?}");
    }

    #[test]
    fn route_table_parsing_prefers_the_longest_prefix() {
        // Little-endian hex as the kernel prints it: 10.0.2.0/24 via eth0,
        // default via eth1, and 10.0.0.0/8 via eth2.
        let table = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
eth1\t00000000\t0102000A\t0003\t0\t0\t0\t00000000\t0\t0\t0
eth2\t0000000A\t00000000\t0001\t0\t0\t0\t000000FF\t0\t0\t0
eth0\t0002000A\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0
";
        let route = |a: &str| route_interface(table, a.parse().expect("literal"));
        assert_eq!(route("10.0.2.5").as_deref(), Some("eth0"));
        assert_eq!(route("10.9.9.9").as_deref(), Some("eth2"));
        assert_eq!(
            route("8.8.8.8").as_deref(),
            Some("eth1"),
            "the default route matches all"
        );
    }

    #[test]
    fn cpuset_lists_are_counted_not_guessed() {
        assert_eq!(count_cpuset("0-3"), 4);
        assert_eq!(count_cpuset("0-3,8"), 5);
        assert_eq!(count_cpuset("2"), 1);
        assert_eq!(count_cpuset(""), 0);
    }

    #[test]
    fn ipv6_peers_report_no_route_rather_than_a_wrong_one() {
        let p = peer_mtu("::1".parse().expect("literal"));
        assert_eq!(p.interface, "unknown");
        assert_eq!(p.mtu, None);
    }
}
