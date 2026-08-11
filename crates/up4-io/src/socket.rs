//! Fabric sockets (spec S6.1).
//!
//! One UDP socket per shard, blocking, with a receive timeout so a shard
//! notices a shutdown request between batches. Buffer sizes are *requested* and
//! then read back: unprivileged processes get whatever the kernel's
//! `net.core.rmem_max` allows, and up4's rule is to report what it was granted
//! rather than to raise a limit it is not allowed to raise (spec S1.1, P3).

use quinn_udp::{RecvMeta, Transmit, UdpSockRef, UdpSocketState};
use serde::Serialize;
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    io::{self, IoSliceMut},
    net::SocketAddr,
    os::fd::AsRawFd,
    time::Duration,
};

/// Receive slots per batched syscall.
///
/// quinn-udp's `recv` caps at its own `BATCH_SIZE`, so asking for more would
/// allocate arena slots that `recvmmsg` can never fill, several MiB per
/// shard.
/// Spec S6.2 names 64; the library's cap is the operative number and is
/// recorded in `docs/deviations.md`.
pub const RX_BATCH: usize = quinn_udp::BATCH_SIZE;

/// Segments staged per destination before a flush is forced (spec S6.3, S9's
/// `tx_batch_size` buckets).
pub const TX_BATCH: usize = 64;

/// Largest payload one segmented (`UDP_SEGMENT`) write may carry.
///
/// A GSO write is one datagram to the kernel until it segments it, so it is
/// bounded by what an IPv4 datagram can hold: 65535 less the 20-byte IP and
/// 8-byte UDP headers. Exceeding it fails with `EMSGSIZE`, which quinn-udp
/// *swallows* (see [`FabricSocket::send`]), so the frames would vanish without
/// a counter. The transmit path partitions batches to respect this.
pub const GSO_MAX_BYTES: usize = 65535 - 20 - 8;

/// Bytes reserved in front of every frame the pipeline sees (spec S7.1).
pub const HEADROOM: usize = 64;

const _: () = assert!(HEADROOM >= up4_engine::MIN_HEADROOM);

/// Socket buffer size requested for both directions (spec S6.1).
pub const WANT_BUF_BYTES: usize = 8 << 20;

/// How long a receive waits for traffic before the loop re-checks the stop flag.
pub const RECV_TIMEOUT: Duration = Duration::from_millis(200);

/// How long a blocked transmit waits for the send buffer to drain before the
/// remainder is dropped and counted (spec S6.3).
pub const SEND_TIMEOUT: Duration = Duration::from_millis(50);

/// What the kernel actually gave us, logged once at startup (spec S6.1).
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub struct SocketCaps {
    /// Granted receive buffer size in bytes.
    pub rcvbuf: usize,
    /// Granted send buffer size in bytes.
    pub sndbuf: usize,
    /// Segments a single GRO read may coalesce; 1 means GRO is unavailable.
    pub gro_segments: usize,
    /// Segments a single GSO write may carry; 1 means GSO is unavailable.
    pub max_gso_segments: usize,
    /// Whether the socket may fragment outgoing datagrams.
    pub may_fragment: bool,
    /// Whether `SO_REUSEPORT` was requested (shards > 1).
    pub reuse_port: bool,
}

impl SocketCaps {
    /// Whether receive offload is in play.
    #[must_use]
    pub const fn gro(self) -> bool {
        self.gro_segments > 1
    }

    /// Whether send offload is in play.
    #[must_use]
    pub const fn gso(self) -> bool {
        self.max_gso_segments > 1
    }
}

/// A bound fabric socket and its offload state.
#[derive(Debug)]
pub struct FabricSocket {
    sock: Socket,
    state: UdpSocketState,
    caps: SocketCaps,
}

impl FabricSocket {
    /// Bind a shard socket to `addr`.
    ///
    /// `reuse_port` must be set when more than one shard shares the address
    /// (spec S6.1); with a single shard it stays off so a second up4d on the
    /// same address fails loudly instead of silently stealing traffic.
    pub fn bind(addr: SocketAddr, reuse_port: bool) -> io::Result<Self> {
        let sock = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
        if reuse_port {
            sock.set_reuse_port(true)?;
        }
        // Requests, not demands: the granted sizes are read back below.
        let _ = sock.set_recv_buffer_size(WANT_BUF_BYTES);
        let _ = sock.set_send_buffer_size(WANT_BUF_BYTES);
        sock.bind(&addr.into())?;
        sock.set_read_timeout(Some(RECV_TIMEOUT))?;

        // quinn-udp probes GRO/GSO here and degrades on its own if either is
        // unavailable, which is the fallback spec S17 requires. It also puts
        // the socket into non-blocking mode for its async users, which up4
        // keeps, deliberately. See `FabricSocket::recv`.
        let state = UdpSocketState::new(UdpSockRef::from(&sock))?;
        let caps = SocketCaps {
            rcvbuf: sock.recv_buffer_size().unwrap_or(0),
            sndbuf: sock.send_buffer_size().unwrap_or(0),
            gro_segments: state.gro_segments(),
            max_gso_segments: state.max_gso_segments(),
            may_fragment: state.may_fragment(),
            reuse_port,
        };
        Ok(Self { sock, state, caps })
    }

    /// The granted capabilities.
    #[must_use]
    pub const fn caps(&self) -> SocketCaps {
        self.caps
    }

    /// The address actually bound, which differs from the requested one when
    /// the configuration asked for port 0.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.sock.local_addr()?.as_socket().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "bound socket is not an IP socket",
            )
        })
    }

    /// Receive whatever has arrived, waiting up to [`RECV_TIMEOUT`] for the
    /// first datagram (spec S6.2 step 1).
    ///
    /// ## Why this is not simply a blocking socket
    ///
    /// `recvmmsg(2)` without `MSG_WAITFORONE` does not return when the first
    /// message arrives; it waits for **all `vlen`** of them. On a blocking
    /// socket that turns a 32-slot batch into a latency trap: a shard sits on
    /// 31 received frames waiting for a 32nd that may be seconds away, while
    /// the peer's queue backs up behind it. quinn-udp passes no flags and
    /// exposes none, so the batch cannot be told to return early.
    ///
    /// The alternative, leaving the socket non-blocking as quinn-udp does,
    /// makes the call return `EAGAIN` immediately and the shard loop a busy
    /// spin, which spec S6.3 forbids and which measurably starves the very
    /// receivers this node is feeding.
    ///
    /// So up4 does what a reactor would: it *asks* for what has arrived, and
    /// waits for readiness only when nothing has. One `poll` syscall when the
    /// link is idle, none when it is busy, and a batch that returns as soon as
    /// there is work.
    ///
    /// FUTURE(io_uring): this and [`FabricSocket::send`] are the only two
    /// places the datapath touches the kernel, so a submission-queue backend
    /// would replace exactly these two methods (spec S6.4 leaves the marker
    /// and forbids the implementation in v1).
    #[inline]
    pub fn recv(&self, bufs: &mut [IoSliceMut<'_>], meta: &mut [RecvMeta]) -> io::Result<usize> {
        match self.state.recv(UdpSockRef::from(&self.sock), bufs, meta) {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                self.wait(libc::POLLIN, RECV_TIMEOUT)?;
                self.state.recv(UdpSockRef::from(&self.sock), bufs, meta)
            }
            other => other,
        }
    }

    /// Send one transmit, which may carry many segments under GSO.
    ///
    /// A full send buffer waits for space rather than spinning; the caller
    /// decides what to do if it is still full afterwards (spec S6.3).
    ///
    /// This calls quinn-udp's `try_send`, not its `send`: the latter reports
    /// `Ok(())` for every error except `WouldBlock`, including `EMSGSIZE`,
    /// which is right for a QUIC MTU probe and wrong for a switch, where a
    /// silently discarded batch is precisely the thing spec S1.6 forbids.
    #[inline]
    pub fn send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        match self.state.try_send(UdpSockRef::from(&self.sock), transmit) {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                self.wait(libc::POLLOUT, SEND_TIMEOUT)?;
                self.state.try_send(UdpSockRef::from(&self.sock), transmit)
            }
            other => other,
        }
    }

    /// Wait for the socket to become ready for `events`, or for `timeout`.
    ///
    /// Returns `Ok(())` in both cases: a timeout is the loop's heartbeat, and
    /// the caller learns the difference from the retried syscall.
    fn wait(&self, events: libc::c_short, timeout: Duration) -> io::Result<()> {
        let mut pollfd = libc::pollfd {
            fd: self.sock.as_raw_fd(),
            events,
            revents: 0,
        };
        // SAFETY: `pollfd` is a live, fully initialized local; `poll` writes
        // only its `revents` field and reads the fd, which `self.sock` keeps
        // open for the duration of the call. The count matches the one-element
        // array, and the timeout is clamped to `c_int` below.
        let rc = unsafe {
            libc::poll(
                &raw mut pollfd,
                1,
                timeout.as_millis().min(i32::MAX as u128) as libc::c_int,
            )
        };
        match rc {
            -1 => match io::Error::last_os_error() {
                // A signal is not a failure; the caller re-checks its stop flag.
                e if e.kind() == io::ErrorKind::Interrupted => Ok(()),
                e => Err(e),
            },
            _ => Ok(()),
        }
    }
}

/// Whether an error means "try again later" rather than "this socket is done".
///
/// A receive timeout is the loop's heartbeat, not a failure, and `EINTR` is
/// what a signal looks like to a blocking syscall.
#[must_use]
pub fn is_transient(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loopback() -> SocketAddr {
        "127.0.0.1:0".parse().expect("literal")
    }

    #[test]
    fn a_bound_socket_reports_what_it_was_granted() {
        let s = FabricSocket::bind(loopback(), false).expect("bind loopback");
        let caps = s.caps();
        assert!(caps.rcvbuf > 0 && caps.sndbuf > 0, "{caps:?}");
        assert!(
            caps.gro_segments >= 1 && caps.max_gso_segments >= 1,
            "{caps:?}"
        );
        assert_ne!(
            s.local_addr().expect("bound").port(),
            0,
            "port 0 resolves to a real port"
        );
    }

    /// A receive on an idle socket must *wait*, not return instantly: an
    /// instant `EAGAIN` here means the shard loop has become a busy spin.
    #[test]
    fn receive_blocks_until_its_timeout_rather_than_spinning() {
        let s = FabricSocket::bind(loopback(), false).expect("bind loopback");
        let mut buf = [0u8; 2048];
        let mut iovs = [IoSliceMut::new(&mut buf)];
        let mut metas = [RecvMeta::default()];

        let start = std::time::Instant::now();
        let err = s.recv(&mut iovs, &mut metas).expect_err("nothing was sent");
        let waited = start.elapsed();

        assert!(is_transient(&err), "{err:?}");
        assert!(
            waited >= RECV_TIMEOUT / 2,
            "receive returned after {waited:?}; the socket is not blocking"
        );
    }

    /// The bound above is not decorative: a write past it fails, and the
    /// failure must reach us rather than being reported as success.
    #[test]
    fn an_oversized_segmented_write_is_reported_as_an_error() {
        let a = FabricSocket::bind(loopback(), false).expect("bind a");
        let b = FabricSocket::bind(loopback(), false).expect("bind b");
        if !a.caps().gso() {
            return; // nothing to bound without GSO
        }
        let segment = 1472;
        let too_many = vec![0u8; GSO_MAX_BYTES + segment];
        let err = a.send(&Transmit {
            destination: b.local_addr().expect("bound"),
            ecn: None,
            contents: &too_many,
            segment_size: Some(segment),
            src_ip: None,
        });
        assert!(
            err.is_err(),
            "a write past GSO_MAX_BYTES must not report success"
        );
    }

    #[test]
    fn a_datagram_round_trips_with_its_source_address() {
        let a = FabricSocket::bind(loopback(), false).expect("bind a");
        let b = FabricSocket::bind(loopback(), false).expect("bind b");
        let dest = b.local_addr().expect("bound");
        a.send(&Transmit {
            destination: dest,
            ecn: None,
            contents: b"hello",
            segment_size: None,
            src_ip: None,
        })
        .expect("send");

        let mut buf = [0u8; 2048];
        let mut iovs = [IoSliceMut::new(&mut buf)];
        let mut metas = [RecvMeta::default()];
        let n = b.recv(&mut iovs, &mut metas).expect("recv");
        assert_eq!(n, 1);
        assert_eq!(metas[0].len, 5);
        assert_eq!(&buf[..5], b"hello");
        assert_eq!(metas[0].addr, a.local_addr().expect("bound"));
    }

    #[test]
    fn two_shards_may_share_an_address_only_with_reuse_port() {
        let first = FabricSocket::bind(loopback(), true).expect("bind first");
        let addr = first.local_addr().expect("bound");
        assert!(
            FabricSocket::bind(addr, true).is_ok(),
            "reuse_port shards share"
        );
        assert!(
            FabricSocket::bind(addr, false).is_err(),
            "without it, binding fails loudly"
        );
    }
}
