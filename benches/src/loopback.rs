//! A one-node fixture on loopback: a real shard, a real socket, real frames.
//!
//! Shared by the I/O benchmarks and by the allocation guard, so all three
//! measure the same code path the switch actually runs.

use quinn_udp::{RecvMeta, Transmit};
use std::{
    io::IoSliceMut,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use up4_config::{Config, VportTable};
use up4_engine::{Pipeline, PipelineParams};
use up4_io::{FabricSocket, Shard, ShardParams, Stop, socket::GSO_MAX_BYTES};
use up4_metrics::Metrics;
use up4_wire::{Hdr, OVERLAY_HDR_LEN, Seq};

/// The fabric's inner MTU for these runs.
pub const INNER_MTU: usize = up4_wire::INNER_MTU_V4;

/// A shard under test, with a peer socket on either side of it.
pub struct Fixture {
    ingress: FabricSocket,
    egress: FabricSocket,
    shard_addr: SocketAddr,
    metrics: Arc<Metrics>,
    stop: Stop,
    thread: Option<std::thread::JoinHandle<()>>,
    seq: u32,
    scratch: Vec<u8>,
    storage: Vec<u8>,
}

impl Fixture {
    /// Start a shard running `pipeline_name`, wired so vport 0 ingresses from
    /// one socket and vport 1 egresses to the other. `setup` installs whatever
    /// control-plane state the benchmark needs before the datapath starts.
    pub fn start(pipeline_name: &str, setup: impl FnOnce(&dyn Pipeline)) -> Self {
        let bind = |port| {
            FabricSocket::bind(format!("127.0.0.1:{port}").parse().expect("literal"), false)
                .expect("bind")
        };
        let ingress = bind(0);
        let egress = bind(0);
        let shard_sock = bind(0);
        let shard_addr = shard_sock.local_addr().expect("bound");

        let src = format!(
            "[node]\nid = \"bench\"\nbind = \"{shard_addr}\"\npipeline = \"{pipeline_name}\"\n\
             ctl_socket = \"/tmp/up4-bench.sock\"\nmetrics_interval_s = 0\n\
             [[vport]]\nid = 0\npeer = \"{}\"\n[[vport]]\nid = 1\npeer = \"{}\"\n",
            ingress.local_addr().expect("bound"),
            egress.local_addr().expect("bound"),
        );
        let config = Config::from_toml(&src, &up4_engine::names()).expect("bench config");
        let topology: Arc<VportTable> = Arc::new(config.vports);
        let metrics = Arc::new(Metrics::new("bench", &topology));

        let pipeline: Arc<dyn Pipeline> = Arc::from(
            up4_engine::build(pipeline_name, &PipelineParams::new([0, 1])).expect("built"),
        );
        setup(&*pipeline);

        let mut shard = Shard::new(
            shard_sock,
            pipeline.engine(),
            ShardParams {
                id: 0,
                topology,
                metrics: Arc::clone(&metrics),
                inner_mtu: INNER_MTU,
                punt: None,
            },
        );
        let stop = Stop::new();
        let thread = {
            let stop = stop.clone();
            std::thread::spawn(move || shard.run(&stop).expect("shard runs"))
        };
        Self {
            ingress,
            egress,
            shard_addr,
            metrics,
            stop,
            thread: Some(thread),
            seq: 0,
            scratch: Vec::with_capacity(64 * (OVERLAY_HDR_LEN + INNER_MTU)),
            storage: vec![0u8; 256 * 1024],
        }
    }

    /// Push `count` copies of `frame` through the shard and read back what
    /// comes out the other side. Returns the number of frames recovered.
    ///
    /// Allocation-free after the first call: both buffers are reused.
    pub fn round_trip(&mut self, frame: &[u8], count: usize) -> usize {
        let segment = OVERLAY_HDR_LEN + frame.len();
        self.scratch.clear();
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
            self.seq = self.seq.wrapping_add(1);
            self.scratch.extend_from_slice(&hdr);
            self.scratch.extend_from_slice(frame);
        }
        // One segmented write can only carry so much; split on the same bound
        // the datapath uses.
        let per_write = (GSO_MAX_BYTES / segment).max(1);
        for chunk in self.scratch.chunks(per_write * segment) {
            let segments = chunk.len().div_ceil(segment);
            self.ingress
                .send(&Transmit {
                    destination: self.shard_addr,
                    ecn: None,
                    contents: chunk,
                    segment_size: (segments > 1).then_some(segment),
                    src_ip: None,
                })
                .expect("send");
        }

        let mut received = 0;
        let deadline = Instant::now() + Duration::from_secs(2);
        while received < count && Instant::now() < deadline {
            let mut iovs = [IoSliceMut::new(&mut self.storage)];
            let mut metas = [RecvMeta::default()];
            let Ok(n) = self.egress.recv(&mut iovs, &mut metas) else {
                continue;
            };
            for meta in metas.iter().take(n) {
                let stride = if meta.stride == 0 {
                    meta.len
                } else {
                    meta.stride
                };
                received += meta.len.div_ceil(stride.max(1));
            }
        }
        received
    }

    /// The shard's counters.
    #[must_use]
    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.request();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Install one entry through the typed shim, the way the control channel does.
pub fn install(
    pipeline: &dyn Pipeline,
    table: &str,
    key: &str,
    action: &str,
    params: &[(&str, &str)],
) {
    let schema = pipeline.tables().schema(table).expect("known table");
    let key = up4_engine::TypedKey::parse(schema.key, key).expect("valid key");
    let signature = schema.action(action).expect("known action");
    let values: Vec<up4_engine::TypedVal> = signature
        .params
        .iter()
        .map(|p| {
            let text = params
                .iter()
                .find(|(n, _)| *n == p.name)
                .expect("parameter given")
                .1;
            up4_engine::TypedVal::parse(p.kind, text).expect("valid parameter")
        })
        .collect();
    pipeline
        .tables()
        .table_add(schema.name, key, action, &values)
        .expect("install");
}

/// Install `count` /24 routes out of vport 1 — the route set A2 measures with.
pub fn install_routes(pipeline: &dyn Pipeline, count: u32) {
    for (key, port) in routes(count) {
        install(
            pipeline,
            "ipv4_lpm",
            &key,
            "forward",
            &[("port", &port), ("dmac", "bb:bb:bb:bb:bb:01")],
        );
    }
}

/// The MAC forwarding entry the l2fwd benchmarks match on.
pub fn install_fdb(pipeline: &dyn Pipeline) {
    install(
        pipeline,
        "mac_dst",
        "02:00:00:00:00:02",
        "forward",
        &[("port", "1")],
    );
}

/// An Ethernet + IPv4 + UDP frame of `len` bytes addressed to `dst_ip`.
#[must_use]
pub fn frame(len: usize, dst_ip: [u8; 4]) -> Vec<u8> {
    let mut f = vec![0u8; len.max(60)];
    let total = f.len();
    f[0..6].copy_from_slice(&[0x02, 0, 0, 0, 0, 2]);
    f[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 1]);
    f[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    f[14] = 0x45;
    f[16..18].copy_from_slice(&((total - 14) as u16).to_be_bytes());
    f[22] = 64;
    f[23] = 17;
    f[24..26].copy_from_slice(&[0xde, 0xad]);
    f[26..30].copy_from_slice(&[10, 0, 1, 1]);
    f[30..34].copy_from_slice(&dst_ip);
    f
}

/// The route set the l3fwd benchmarks use: `count` /24s out of vport 1.
#[must_use]
pub fn routes(count: u32) -> Vec<(String, String)> {
    (0..count)
        .map(|i| {
            let addr = std::net::Ipv4Addr::from(0x0a00_0000 | (i << 8));
            (format!("{addr}/24"), "1".to_owned())
        })
        .collect()
}
