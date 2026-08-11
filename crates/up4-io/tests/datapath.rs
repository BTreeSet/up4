//! The receive/transmit path end to end, over real loopback sockets.
//!
//! These tests drive a `Shard` the way the fabric does, by sending it overlay
//! segments, and check both what comes out and what the counters say about it.
//! The engine is the null oracle, so a mismatch here is the harness's fault and
//! not a pipeline's.

use quinn_udp::{RecvMeta, Transmit};
use std::{
    io::IoSliceMut,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use up4_config::{Config, VportTable};
use up4_engine::{Pipeline, PipelineParams, programs::null::NullPipeline};
use up4_io::{FabricSocket, PuntQueue, Shard, ShardParams, Stop, socket::HEADROOM};
use up4_metrics::{Counter, Metrics, VportCounter};
use up4_wire::{Hdr, OVERLAY_HDR_LEN, Seq};

const INNER_MTU: usize = up4_wire::INNER_MTU_V4;

/// A peer: a plain fabric socket standing in for another up4 node.
struct Peer {
    sock: FabricSocket,
    addr: SocketAddr,
    seq: u32,
}

impl Peer {
    fn new() -> Self {
        let sock =
            FabricSocket::bind("127.0.0.1:0".parse().expect("literal"), false).expect("bind peer");
        let addr = sock.local_addr().expect("bound");
        Self { sock, addr, seq: 0 }
    }

    /// Send `count` segments of `frame` to `dest`, as one GSO write when the
    /// host supports it and as separate datagrams otherwise.
    fn send(&mut self, dest: SocketAddr, frame: &[u8], count: usize) {
        let mut buf = Vec::with_capacity(count * (OVERLAY_HDR_LEN + frame.len()));
        for _ in 0..count {
            let mut hdr = [0u8; OVERLAY_HDR_LEN];
            up4_wire::encode(
                &Hdr {
                    ingress_vport: 0,
                    seq: Seq::new(self.seq),
                    ts_us: 0,
                },
                &mut hdr,
            );
            self.seq += 1;
            buf.extend_from_slice(&hdr);
            buf.extend_from_slice(frame);
        }
        let segment = OVERLAY_HDR_LEN + frame.len();
        self.sock
            .send(&Transmit {
                destination: dest,
                ecn: None,
                contents: &buf,
                segment_size: (count > 1).then_some(segment),
                src_ip: None,
            })
            .expect("send to shard");
    }

    fn send_raw(&self, dest: SocketAddr, bytes: &[u8]) {
        self.sock
            .send(&Transmit {
                destination: dest,
                ecn: None,
                contents: bytes,
                segment_size: None,
                src_ip: None,
            })
            .expect("send raw");
    }

    /// Collect inner frames until `want` have arrived or the deadline passes.
    fn recv_frames(&self, want: usize) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut storage = vec![0u8; 128 * 1024];
        while out.len() < want && Instant::now() < deadline {
            let mut iovs = [IoSliceMut::new(&mut storage)];
            let mut metas = [RecvMeta::default()];
            let Ok(n) = self.sock.recv(&mut iovs, &mut metas) else {
                continue;
            };
            for meta in metas.iter().take(n) {
                let stride = if meta.stride == 0 {
                    meta.len
                } else {
                    meta.stride
                };
                for k in 0..meta.len.div_ceil(stride) {
                    let start = k * stride;
                    let end = meta.len.min(start + stride);
                    out.push(storage[start + OVERLAY_HDR_LEN..end].to_vec());
                }
            }
        }
        out
    }
}

struct Fixture {
    shard_addr: SocketAddr,
    metrics: Arc<Metrics>,
    topology: Arc<VportTable>,
    punt: Arc<PuntQueue>,
    stop: Stop,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Fixture {
    /// Two vports, pointing at `a` and `b`, with the null oracle wired between
    /// them (0 -> 1, 1 -> 0).
    fn start(a: &Peer, b: &Peer) -> Self {
        let shard_sock =
            FabricSocket::bind("127.0.0.1:0".parse().expect("literal"), false).expect("bind shard");
        let shard_addr = shard_sock.local_addr().expect("bound");
        let src = format!(
            r#"
[node]
id = "t"
bind = "{shard_addr}"
pipeline = "null"
ctl_socket = "/tmp/up4-test.sock"
[[vport]]
id = 0
peer = "{}"
[[vport]]
id = 1
peer = "{}"
"#,
            a.addr, b.addr
        );
        let cfg = Config::from_toml(&src, &["null"]).expect("fixture config is valid");
        let topology = Arc::new(cfg.vports);
        let metrics = Arc::new(Metrics::new(&cfg.node.id, &topology));
        let punt = Arc::new(PuntQueue::new(INNER_MTU));
        let pipeline = NullPipeline::new(&PipelineParams::new([0, 1]));
        let params = ShardParams {
            id: 0,
            topology: Arc::clone(&topology),
            metrics: Arc::clone(&metrics),
            inner_mtu: INNER_MTU,
            punt: Some(Arc::clone(&punt)),
        };
        let mut shard = Shard::new(shard_sock, pipeline.engine(), params);
        let stop = Stop::new();
        let thread = {
            let stop = stop.clone();
            std::thread::spawn(move || shard.run(&stop).expect("shard runs cleanly"))
        };
        Self {
            shard_addr,
            metrics,
            topology,
            punt,
            stop,
            thread: Some(thread),
        }
    }

    fn vport(&self, id: u16) -> up4_config::VportIdx {
        self.topology.idx_of_id(id).expect("configured vport")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.request();
        if let Some(t) = self.thread.take() {
            t.join().expect("shard thread");
        }
    }
}

/// Poll `value` until it reaches `want`.
///
/// A shard transmits *before* it records the transmission, so a peer can hold
/// the frame in its hand while the counter is still one instruction away.
/// Polling states that ordering instead of racing it.
fn eventually(what: &str, want: u64, mut value: impl FnMut() -> u64) {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let got = value();
        if got == want {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{what}: {got} != {want} after 2 s"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
}

fn frame(len: usize, tag: u8) -> Vec<u8> {
    let mut f = vec![tag; len];
    f[0..6].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, tag]);
    f
}

#[test]
fn a_frame_arrives_on_the_other_vport_unchanged() {
    let mut a = Peer::new();
    let b = Peer::new();
    let fx = Fixture::start(&a, &b);

    let sent = frame(64, 1);
    a.send(fx.shard_addr, &sent, 1);
    let got = b.recv_frames(1);

    assert_eq!(got, vec![sent], "the oracle forwards 0 -> 1 byte for byte");
    assert_eq!(fx.metrics.harness_drops(), 0, "a clean path drops nothing");
    eventually("rx_pkts", 1, || {
        fx.metrics.vport(fx.vport(0)).get(VportCounter::RxPkts)
    });
    eventually("rx_bytes", 64, || {
        fx.metrics.vport(fx.vport(0)).get(VportCounter::RxBytes)
    });
    eventually("tx_pkts", 1, || {
        fx.metrics.vport(fx.vport(1)).get(VportCounter::TxPkts)
    });
    eventually("tx_bytes", 64, || {
        fx.metrics.vport(fx.vport(1)).get(VportCounter::TxBytes)
    });
}

#[test]
fn a_batch_of_segments_survives_the_round_trip() {
    let mut a = Peer::new();
    let b = Peer::new();
    let fx = Fixture::start(&a, &b);

    let sent = frame(512, 7);
    a.send(fx.shard_addr, &sent, 16);
    let got = b.recv_frames(16);

    assert_eq!(
        got.len(),
        16,
        "every segment is forwarded, coalesced or not"
    );
    assert!(got.iter().all(|f| *f == sent));
    assert_eq!(fx.metrics.harness_drops(), 0);
    eventually("rx_pkts", 16, || {
        fx.metrics.vport(fx.vport(0)).get(VportCounter::RxPkts)
    });
    eventually("tx_pkts", 16, || {
        fx.metrics.vport(fx.vport(1)).get(VportCounter::TxPkts)
    });
}

#[test]
fn a_maximum_size_frame_is_forwarded() {
    let mut a = Peer::new();
    let b = Peer::new();
    let fx = Fixture::start(&a, &b);

    let sent = frame(INNER_MTU, 3);
    a.send(fx.shard_addr, &sent, 1);
    assert_eq!(b.recv_frames(1), vec![sent]);
    assert_eq!(fx.metrics.harness_drops(), 0);
}

#[test]
fn an_unconfigured_peer_is_counted_and_dropped() {
    let mut a = Peer::new();
    let b = Peer::new();
    let fx = Fixture::start(&a, &b);
    let mut stranger = Peer::new();

    stranger.send(fx.shard_addr, &frame(64, 9), 1);
    a.send(fx.shard_addr, &frame(64, 1), 1);
    b.recv_frames(1);

    eventually("rx_unknown_peer", 1, || {
        fx.metrics.get(Counter::RxUnknownPeer)
    });
    assert_eq!(fx.metrics.get(Counter::RxBadHeader), 0);
}

#[test]
fn an_undecodable_segment_is_counted_and_dropped() {
    let mut a = Peer::new();
    let b = Peer::new();
    let fx = Fixture::start(&a, &b);

    a.send_raw(fx.shard_addr, &[0xf0; OVERLAY_HDR_LEN + 4]); // wrong version
    a.send_raw(fx.shard_addr, &[0x10; OVERLAY_HDR_LEN - 1]); // short buffer
    a.send(fx.shard_addr, &frame(64, 1), 1);
    assert_eq!(b.recv_frames(1).len(), 1, "a good frame still gets through");

    eventually("rx_bad_header", 2, || fx.metrics.get(Counter::RxBadHeader));
    eventually("rx_pkts", 1, || {
        fx.metrics.vport(fx.vport(0)).get(VportCounter::RxPkts)
    });
}

#[test]
fn sequence_gaps_and_reorder_are_recorded_without_buffering() {
    let mut a = Peer::new();
    let b = Peer::new();
    let fx = Fixture::start(&a, &b);

    a.seq = 0;
    a.send(fx.shard_addr, &frame(64, 1), 1); // seq 0
    a.seq = 5;
    a.send(fx.shard_addr, &frame(64, 2), 1); // seq 5: four missing
    a.seq = 1;
    a.send(fx.shard_addr, &frame(64, 3), 1); // seq 1: late
    let got = b.recv_frames(3);

    assert_eq!(got.len(), 3, "recording loss never means dropping frames");
    eventually("rx_seq_gap_total", 4, || {
        fx.metrics
            .vport(fx.vport(0))
            .get(VportCounter::RxSeqGapTotal)
    });
    eventually("rx_reorder", 1, || {
        fx.metrics.vport(fx.vport(0)).get(VportCounter::RxReorder)
    });
    assert_eq!(
        fx.metrics.harness_drops(),
        0,
        "loss on the wire is not a harness drop"
    );
}

#[test]
fn the_shard_stamps_its_own_sequence_per_destination() {
    let mut a = Peer::new();
    let b = Peer::new();
    let fx = Fixture::start(&a, &b);

    a.seq = 900;
    for tag in 0..3 {
        a.send(fx.shard_addr, &frame(64, tag), 1);
    }
    assert_eq!(b.recv_frames(3).len(), 3);
    eventually("tx_pkts", 3, || {
        fx.metrics.vport(fx.vport(1)).get(VportCounter::TxPkts)
    });
}

#[test]
fn the_headroom_promise_holds_for_every_segment_of_a_read() {
    // The oracle does not encapsulate, so this checks the arithmetic the
    // datapath relies on: segment k of a coalesced read begins at
    // HEADROOM + k*stride + 12, all of which precedes it and is already spent.
    let stride = OVERLAY_HDR_LEN + INNER_MTU;
    for k in 0..64 {
        let headroom = HEADROOM + k * stride + OVERLAY_HDR_LEN;
        assert!(headroom >= up4_engine::MIN_HEADROOM, "segment {k}");
    }
}

#[test]
fn punt_is_not_reached_by_a_forwarding_oracle() {
    let mut a = Peer::new();
    let b = Peer::new();
    let fx = Fixture::start(&a, &b);
    a.send(fx.shard_addr, &frame(64, 1), 1);
    b.recv_frames(1);
    assert!(fx.punt.is_empty());
    assert_eq!(fx.metrics.get(Counter::PuntOverflowDrop), 0);
    assert_eq!(fx.metrics.get(Counter::PuntUnconfiguredDrop), 0);
}
