//! Two routers, two traffic generators, real processes, real sockets.
//!
//! This is the proof the MVP exists to produce: a P4 program's semantics,
//! executed by an unprivileged userspace process, forwarding real Ethernet
//! frames between two switches over plain UDP — in both directions at once,
//! with every lost frame attributable.
//!
//! ```text
//!  pktgen A <--> node A <--> node B <--> pktgen B
//!    :PA   vp0    :NA   vp1  vp1  :NB   vp0   :PB
//! ```
//!
//! Node A routes 10.0.2.0/24 toward B and 10.0.1.0/24 back to pktgen A; node B
//! mirrors it. Generator A sources 10.0.1.1 -> 10.0.2.1 and generator B the
//! reverse, so every frame crosses both switches.

mod harness;

use harness::{Node, NodeSpec, Ports, TempDir, wait_until};
use quinn_udp::{RecvMeta, Transmit};
use std::{io::IoSliceMut, net::SocketAddr, time::Duration};
use up4_ctl::{EntrySpec, Params, Request, Response};
use up4_engine::headers::{ETH_HDR_LEN, Ethernet, Ipv4};
use up4_io::{FabricSocket, Stop};
use up4_tools::{PktgenConfig, frame::FrameSpec};
use up4_wire::{Hdr, OVERLAY_HDR_LEN, Seq};

/// Routes for one node: where the two subnets live from its point of view.
fn routes(to_b: u16, to_a: u16) -> String {
    format!(
        r#"{{"entries":[
        {{"table":"ipv4_lpm","key":"10.0.2.0/24","action":"forward",
          "params":{{"port":"{to_b}","dmac":"02:00:00:00:00:02"}}}},
        {{"table":"ipv4_lpm","key":"10.0.1.0/24","action":"forward",
          "params":{{"port":"{to_a}","dmac":"02:00:00:00:00:01"}}}}
    ]}}"#
    )
}

/// The four-address topology, with both nodes running and routed.
struct Fabric {
    _dir: TempDir,
    /// Held for the fixture's lifetime; see [`harness::exclusive`].
    _guard: std::sync::MutexGuard<'static, ()>,
    a: Node,
    b: Node,
    /// pktgen A's address, a peer of node A.
    pa: SocketAddr,
    /// pktgen B's address, a peer of node B.
    pb: SocketAddr,
    /// Node A's fabric address.
    na: SocketAddr,
    /// Node B's fabric address.
    nb: SocketAddr,
}

impl Fabric {
    fn start(tag: &str, punt: bool, metrics_interval_s: u64) -> Self {
        Self::start_on(tag, punt, metrics_interval_s, None)
    }

    /// The same fabric with both nodes running `backend`. A *program* is
    /// configured; which backend executes it is a separate axis, so this
    /// changes nothing else about the topology, the routes, or the traffic.
    fn start_on(tag: &str, punt: bool, metrics_interval_s: u64, backend: Option<&str>) -> Self {
        let guard = harness::exclusive();
        let dir = TempDir::new(tag);
        let mut ports = Ports::reserve(4);
        let (na, nb, pa, pb) = (ports.addr(0), ports.addr(1), ports.addr(2), ports.addr(3));
        ports.release();

        let a = Node::start(
            &dir,
            &NodeSpec {
                id: "a",
                bind: na,
                pipeline: "l3fwd",
                vports: &[(0, pa), (1, nb)],
                punt,
                metrics_interval_s,
                // From A: subnet 2 is out vport 1 (toward B), subnet 1 is out
                // vport 0 (toward the generator).
                tables: Some(routes(1, 0)),
                backend,
            },
        );
        let b = Node::start(
            &dir,
            &NodeSpec {
                id: "b",
                bind: nb,
                pipeline: "l3fwd",
                vports: &[(0, pb), (1, na)],
                punt,
                metrics_interval_s,
                // From B: subnet 2 is out vport 0 (toward its generator),
                // subnet 1 is out vport 1 (toward A).
                tables: Some(routes(0, 1)),
                backend,
            },
        );
        Self {
            _dir: dir,
            _guard: guard,
            a,
            b,
            pa,
            pb,
            na,
            nb,
        }
    }
}

/// A generator configuration for one end of the fabric.
fn generator(bind: SocketAddr, target: SocketAddr, src: &str, dst: &str) -> PktgenConfig {
    PktgenConfig {
        bind,
        target,
        frame: FrameSpec {
            src_ip: src.parse().expect("literal"),
            dst_ip: dst.parse().expect("literal"),
            len: 1460,
            ..FrameSpec::default()
        },
        rate_pps: 10_000,
        flows: 4,
        duration: Duration::from_secs(2),
        vport: 0,
        batch: 8,
        same_host: true,
    }
}

#[test]
fn two_routers_carry_two_generators_in_both_directions() {
    let fabric = Fabric::start("bidir", false, 0);

    let west = generator(fabric.pa, fabric.na, "10.0.1.1", "10.0.2.1");
    let east = generator(fabric.pb, fabric.nb, "10.0.2.1", "10.0.1.1");
    let stop = Stop::new();

    let (a_report, b_report) = std::thread::scope(|scope| {
        let stop_east = stop.clone();
        let east_run = scope.spawn(move || up4_tools::run(&east, &stop_east).expect("generator B"));
        let west_report = up4_tools::run(&west, &stop).expect("generator A");
        (west_report, east_run.join().expect("generator B thread"))
    });

    for (label, report) in [("A->B", &a_report), ("B->A", &b_report)] {
        assert!(
            report.sent >= 15_000,
            "{label}: only {} frames sent",
            report.sent
        );
        assert_eq!(report.bad_header, 0, "{label}: undecodable segments");
        assert_eq!(
            report.length_mismatch, 0,
            "{label}: frames changed length in transit"
        );
        // Delivery is generous on purpose: a shared CI box can drop frames in
        // a kernel queue, and that is not up4's fault. What is up4's fault —
        // and is checked strictly below — is failing to *say* so.
        assert!(
            report.received >= report.sent * 95 / 100,
            "{label}: {} of {} frames came back ({:.2}% loss)\n  a: {:?}\n  b: {:?}",
            report.received,
            report.sent,
            report.loss_pct,
            fabric.a.counters().vports,
            fabric.b.counters().vports
        );
        let latency = report
            .latency
            .as_ref()
            .expect("frames returned, so latency was measured");
        assert!(latency.calibrated);
        assert!(
            latency.p99_us < 100_000,
            "{label}: p99 {} us",
            latency.p99_us
        );
    }

    // Nothing was lost by the harness on either node: every frame either
    // forwarded or was accounted for by the pipeline (spec S9).
    for node in [&fabric.a, &fabric.b] {
        let counters = node.counters();
        assert_eq!(
            counters.harness_drops, 0,
            "{} dropped: {:?}",
            counters.node, counters.counters
        );
        assert_eq!(
            counters.counters["engine_drop"], 0,
            "{}: unrouted frames",
            counters.node
        );
    }

    // Spec A5, rehearsed: whatever went missing is *attributable*. Each frame
    // lost in a kernel queue shows up as a sequence gap at the hop that lost
    // it — at a node for the fabric hops, at the generator for the last one —
    // so the accounting closes to within the frames still in flight when the
    // generators stopped.
    let gaps_at = |node: &Node| {
        node.vport_counter(0, "rx_seq_gap_total") + node.vport_counter(1, "rx_seq_gap_total")
    };
    let sent: u64 = a_report.sent + b_report.sent;
    let received: u64 = a_report.received + b_report.received;
    let missing = sent.saturating_sub(received);
    let attributed = a_report.seq_gap_total
        + b_report.seq_gap_total
        + gaps_at(&fabric.a)
        + gaps_at(&fabric.b)
        + fabric.a.counters().harness_drops
        + fabric.b.counters().harness_drops;
    assert!(
        attributed + sent / 100 >= missing,
        "{missing} frames missing of {sent}, only {attributed} attributed; \
         loss must be explainable, not merely small"
    );

    // Node A received on vport 0 and transmitted on vport 1, and vice versa.
    assert!(fabric.a.vport_counter(0, "rx_pkts") >= 15_000);
    assert!(fabric.a.vport_counter(1, "tx_pkts") >= 15_000);
    assert!(fabric.b.vport_counter(1, "rx_pkts") >= 15_000);
    assert!(fabric.b.vport_counter(0, "tx_pkts") >= 15_000);
}

#[test]
fn one_frame_crosses_both_routers_with_the_pipeline_s_edits_applied() {
    let fabric = Fabric::start("single", false, 0);
    let (sent, got) = cross(&fabric);
    assert_edits(&sent, &got);
}

/// The same frame through the same two routers, on each *compiled* backend.
///
/// The conformance corpus already holds all three backends to the same
/// verdicts and bytes, but it calls `Engine::process` directly. This is the
/// rest of the claim: a backend is interchangeable only if the whole datapath
/// — config, control channel, shard threads, sockets, GRO/GSO — works with it,
/// and that is not something a corpus can show.
#[test]
fn every_backend_forwards_across_both_routers() {
    for backend in ["x4c", "ubpf"] {
        let fabric = Fabric::start_on(&format!("backend-{backend}"), false, 0, Some(backend));
        let (sent, got) = cross(&fabric);
        assert_edits(&sent, &got);
    }
}

/// Push one frame in at pktgen A's socket and take it out at pktgen B's,
/// returning what was sent and what arrived.
fn cross(fabric: &Fabric) -> (Vec<u8>, Vec<u8>) {
    // Stand in for the generators with plain sockets, so the frame's bytes are
    // checked rather than counted.
    let west = FabricSocket::bind(fabric.pa, false).expect("bind west");
    let east = FabricSocket::bind(fabric.pb, false).expect("bind east");

    let mut frame = up4_tools::frame::FrameTemplate::new(FrameSpec {
        src_ip: "10.0.1.1".parse().expect("literal"),
        dst_ip: "10.0.2.1".parse().expect("literal"),
        len: 200,
        ..FrameSpec::default()
    });
    let sent = frame.for_flow(0, 1).to_vec();

    let mut segment = Vec::new();
    let mut hdr = [0u8; OVERLAY_HDR_LEN];
    up4_wire::encode(
        &Hdr {
            ingress_vport: 0,
            seq: Seq::new(0),
            ts_us: 7,
        },
        &mut hdr,
    );
    segment.extend_from_slice(&hdr);
    segment.extend_from_slice(&sent);
    west.send(&Transmit {
        destination: fabric.na,
        ecn: None,
        contents: &segment,
        segment_size: None,
        src_ip: None,
    })
    .expect("send one frame");

    let mut storage = vec![0u8; 8192];
    let mut received = None;
    for _ in 0..40 {
        let mut iovs = [IoSliceMut::new(&mut storage)];
        let mut metas = [RecvMeta::default()];
        if let Ok(n) = east.recv(&mut iovs, &mut metas)
            && n == 1
        {
            received = Some(storage[OVERLAY_HDR_LEN..metas[0].len].to_vec());
            break;
        }
    }
    let got = received.unwrap_or_else(|| {
        panic!(
            "the frame did not reach the far generator\n  a: {:?}\n  b: {:?}",
            fabric.a.counters(),
            fabric.b.counters()
        )
    });

    (sent, got)
}

/// What `l3fwd` must have done to the frame, whichever backend ran it.
fn assert_edits(sent: &[u8], got: &[u8]) {
    assert_eq!(got.len(), sent.len(), "length is preserved end to end");
    let before = Ipv4::parse(sent, ETH_HDR_LEN).expect("ipv4");
    let after = Ipv4::parse(got, ETH_HDR_LEN).expect("ipv4");
    assert_eq!(after.ttl, before.ttl - 2, "one decrement per router");
    assert_eq!(after.src, before.src);
    assert_eq!(after.dst, before.dst);
    assert_eq!(
        Ethernet::parse(got).expect("ethernet").dst.to_string(),
        "02:00:00:00:00:02",
        "each hop rewrote the destination MAC from its route"
    );
    assert_eq!(
        &got[24..26],
        &[0, 0],
        "the IPv4 checksum is zero-filled, never recomputed"
    );
    // The program's deparser cannot write this one: the transport header is
    // bytes it never parsed. It is the envelope's `Scrub`, so every backend
    // owes it (spec S1.5).
    assert_eq!(&got[40..42], &[0, 0], "and so is the UDP checksum");
    assert_eq!(
        &got[ETH_HDR_LEN + 20 + 8..],
        &sent[ETH_HDR_LEN + 20 + 8..],
        "payload untouched"
    );
}

#[test]
fn a_route_added_over_the_control_channel_takes_effect_immediately() {
    let fabric = Fabric::start("tableadd", false, 0);
    let west = FabricSocket::bind(fabric.pa, false).expect("bind west");
    let east = FabricSocket::bind(fabric.pb, false).expect("bind east");

    let mut frame = up4_tools::frame::FrameTemplate::new(FrameSpec {
        src_ip: "10.0.1.1".parse().expect("literal"),
        // No route covers this subnet yet, so both nodes drop it.
        dst_ip: "10.9.9.9".parse().expect("literal"),
        len: 128,
        ..FrameSpec::default()
    });
    let payload = frame.for_flow(0, 1).to_vec();
    let mut segment = vec![0u8; OVERLAY_HDR_LEN];
    let (hdr, _) = segment.split_at_mut(OVERLAY_HDR_LEN);
    up4_wire::encode(
        &Hdr {
            ingress_vport: 0,
            seq: Seq::new(0),
            ts_us: 0,
        },
        hdr.try_into().expect("exactly the header"),
    );
    segment.extend_from_slice(&payload);
    let send = |seq: u32| {
        let mut s = segment.clone();
        let mut h = [0u8; OVERLAY_HDR_LEN];
        up4_wire::encode(
            &Hdr {
                ingress_vport: 0,
                seq: Seq::new(seq),
                ts_us: 0,
            },
            &mut h,
        );
        s[..OVERLAY_HDR_LEN].copy_from_slice(&h);
        west.send(&Transmit {
            destination: fabric.na,
            ecn: None,
            contents: &s,
            segment_size: None,
            src_ip: None,
        })
        .expect("send");
    };

    send(0);
    wait_until(Duration::from_secs(2), || {
        fabric.a.counter("engine_drop") >= 1
    });

    // Install the route on both nodes and time how long the change takes to
    // show up in forwarding (spec A4: under 100 ms).
    let add = |node: &Node, port: &str| {
        let response = node.call(&Request::TableAdd {
            entries: vec![EntrySpec {
                table: "ipv4_lpm".into(),
                key: "10.9.9.0/24".into(),
                action: "forward".into(),
                params: Params::from_args(&[
                    format!("port={port}"),
                    "dmac=02:00:00:00:00:02".to_owned(),
                ]),
            }],
        });
        assert_eq!(response, Response::Applied { count: 1 });
    };
    add(&fabric.a, "1");
    add(&fabric.b, "0");

    let mut storage = vec![0u8; 8192];
    let mut seq = 1;
    let visible = wait_until(Duration::from_secs(2), || {
        send(seq);
        seq += 1;
        let mut iovs = [IoSliceMut::new(&mut storage)];
        let mut metas = [RecvMeta::default()];
        east.recv(&mut iovs, &mut metas).is_ok_and(|n| n == 1)
    });
    assert!(
        visible < Duration::from_millis(100),
        "a table change took {visible:?} to reach the datapath"
    );
    assert_eq!(
        fabric.a.counters().harness_drops,
        0,
        "unrouted frames are the pipeline's drop"
    );
}

#[test]
fn a_punt_route_delivers_frames_to_the_control_channel() {
    let fabric = Fabric::start("punt", true, 0);
    let west = FabricSocket::bind(fabric.pa, false).expect("bind west");

    assert_eq!(
        fabric.a.call(&Request::TableAdd {
            entries: vec![EntrySpec {
                table: "ipv4_lpm".into(),
                key: "10.7.0.0/16".into(),
                action: "punt".into(),
                params: Params::default(),
            }],
        }),
        Response::Applied { count: 1 }
    );

    let mut frame = up4_tools::frame::FrameTemplate::new(FrameSpec {
        src_ip: "10.0.1.1".parse().expect("literal"),
        dst_ip: "10.7.1.1".parse().expect("literal"),
        len: 128,
        ..FrameSpec::default()
    });
    let inner = frame.for_flow(0, 1).to_vec();
    let mut segment = [0u8; OVERLAY_HDR_LEN].to_vec();
    up4_wire::encode(
        &Hdr {
            ingress_vport: 0,
            seq: Seq::new(0),
            ts_us: 1234,
        },
        (&mut segment[..OVERLAY_HDR_LEN])
            .try_into()
            .expect("exactly the header"),
    );
    segment.extend_from_slice(&inner);
    west.send(&Transmit {
        destination: fabric.na,
        ecn: None,
        contents: &segment,
        segment_size: None,
        src_ip: None,
    })
    .expect("send");

    let mut drained = Vec::new();
    wait_until(Duration::from_secs(2), || {
        match fabric.a.call(&Request::PuntDrain { max: 8 }) {
            Response::Punted { frames, .. } => {
                drained.extend(frames);
                !drained.is_empty()
            }
            other => panic!("punt-drain replied {other:?}"),
        }
    });

    assert_eq!(drained.len(), 1);
    assert_eq!(
        drained[0].ingress_vport, 0,
        "the frame remembers where it came from"
    );
    let bytes = up4_ctl::b64::decode(&drained[0].frame_b64).expect("valid base64");
    assert_eq!(
        bytes, inner,
        "punted frames arrive byte for byte, overlay stripped"
    );
    assert_eq!(fabric.a.counters().harness_drops, 0);
}

#[test]
fn a_frame_for_an_unconfigured_peer_is_attributed_to_the_harness() {
    let fabric = Fabric::start("stranger", false, 0);
    // A socket the topology knows nothing about.
    let stranger =
        FabricSocket::bind("127.0.0.1:0".parse().expect("literal"), false).expect("bind stranger");
    let mut segment = [0u8; OVERLAY_HDR_LEN].to_vec();
    up4_wire::encode(
        &Hdr {
            ingress_vport: 0,
            seq: Seq::new(0),
            ts_us: 0,
        },
        (&mut segment[..OVERLAY_HDR_LEN])
            .try_into()
            .expect("exactly the header"),
    );
    segment.extend_from_slice(&[0u8; 64]);
    stranger
        .send(&Transmit {
            destination: fabric.na,
            ecn: None,
            contents: &segment,
            segment_size: None,
            src_ip: None,
        })
        .expect("send");

    wait_until(Duration::from_secs(2), || {
        fabric.a.counter("rx_unknown_peer") == 1
    });
    assert_eq!(
        fabric.a.counter("engine_drop"),
        0,
        "the pipeline never saw it"
    );
    assert_eq!(fabric.a.counters().harness_drops, 1);
}

#[test]
fn sigterm_writes_a_final_snapshot_and_exits_zero() {
    let fabric = Fabric::start("sigterm", false, 1);
    // Keep the temporary directory alive: the snapshot file is read below.
    let Fabric {
        _dir: dir,
        _guard,
        a,
        b,
        ..
    } = fabric;

    let status = a.terminate();
    assert_eq!(status.code(), Some(0), "kill -TERM is a clean exit (A6)");

    let jsonl = dir.join("up4-metrics-a.jsonl");
    let text = std::fs::read_to_string(&jsonl).expect("the node wrote its snapshot file");
    let last = text
        .lines()
        .next_back()
        .expect("at least one snapshot line");
    let snapshot: up4_metrics::Snapshot = serde_json::from_str(last).expect("valid JSONL");
    assert_eq!(snapshot.node, "a");
    assert_eq!(snapshot.harness_drops, 0);

    // The peer is unaffected: it keeps answering and counting silence (A6).
    assert_eq!(b.call(&Request::Ping), Response::Pong);
    assert_eq!(b.counters().harness_drops, 0);
}

#[test]
fn killing_one_node_leaves_its_peer_running() {
    let fabric = Fabric::start("kill", false, 0);
    let Fabric {
        _dir, _guard, a, b, ..
    } = fabric;
    let before = b.counter("syscalls_rx");
    a.kill();

    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        b.call(&Request::Ping),
        Response::Pong,
        "the peer survives (A6)"
    );
    let after = b.counter("syscalls_rx");
    assert!(
        after >= before,
        "the peer keeps polling rather than spinning or dying"
    );
    assert_eq!(b.counters().harness_drops, 0);
    assert_eq!(b.shutdown().code(), Some(0), "and still shuts down cleanly");
}

#[test]
fn info_reports_the_pipeline_topology_and_probe() {
    let fabric = Fabric::start("info", true, 0);
    let Response::Info(info) = fabric.a.call(&Request::Info) else {
        panic!("info replies with info");
    };
    assert_eq!(info.node, "a");
    assert_eq!(info.pipeline, "l3fwd/native");
    assert_eq!(info.threads, 1);
    assert_eq!(info.inner_mtu, 1460);
    assert!(info.punt_enabled);
    assert_eq!(info.vports.len(), 2);
    assert!(
        info.probe.get("kernel").is_some(),
        "the startup probe is attached"
    );

    let response = fabric.a.call(&Request::Tables);
    let Response::Tables { tables: schemas } = response else {
        panic!("tables replied {response:?}");
    };
    assert_eq!(schemas.len(), 1);
    assert_eq!(schemas[0].name, "ipv4_lpm");

    let Response::Entries { entries, default } = fabric.a.call(&Request::TableDump {
        table: "ipv4_lpm".into(),
    }) else {
        panic!("dump replies with entries");
    };
    assert_eq!(
        entries.len(),
        2,
        "the startup batch is installed before traffic starts"
    );
    assert_eq!(default.action, "drop");
}
