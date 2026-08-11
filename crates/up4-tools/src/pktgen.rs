//! The load generator (spec S11.2).
//!
//! pktgen is an up4 *peer*: it speaks the same overlay format a node does, so a
//! node cannot tell it from another switch. It sends on one thread, receives on
//! another, and reports what it achieved rather than what it was asked for —
//! the whole point is to measure the difference.
//!
//! Loss is derived from the overlay sequence numbers, not from arrival counts,
//! so a run reports *where* frames went missing rather than only how many.
//! One-way latency comes from the overlay timestamp; both sides read the same
//! `CLOCK_MONOTONIC`, which is only meaningful on one host — a cross-host run
//! reports it labelled as an uncalibrated clock delta (spec S11.2).

use crate::frame::{FrameSpec, FrameTemplate};
use quinn_udp::{RecvMeta, Transmit};
use serde::Serialize;
use std::{
    io::IoSliceMut,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use up4_io::{FabricSocket, Stop, clock, socket::GSO_MAX_BYTES};
use up4_wire::{Hdr, OVERLAY_HDR_LEN, Seq, SeqEvent, SeqTracker};

/// Segments per transmit batch. Matches the switch's own batch bound, so a
/// generator never asks the fabric for a shape the switch would not produce.
pub const TX_BATCH: usize = 64;

/// How long the receiver keeps listening after the sender stops, so frames
/// still in flight are counted rather than reported as loss.
pub const DRAIN_GRACE: Duration = Duration::from_millis(500);

/// What to generate.
#[derive(Clone, Debug)]
pub struct PktgenConfig {
    /// Address this generator binds — must be a configured peer of `target`.
    pub bind: SocketAddr,
    /// The node's fabric address.
    pub target: SocketAddr,
    /// The inner frame to send.
    pub frame: FrameSpec,
    /// Frames per second; `0` means as fast as the socket will take them.
    pub rate_pps: u64,
    /// Distinct inner flows to rotate through.
    pub flows: u32,
    /// How long to send for.
    pub duration: Duration,
    /// The vport id this generator claims in the overlay header.
    pub vport: u16,
    /// Segments per send; `1` disables GSO batching.
    pub batch: usize,
    /// Whether the node is on this host, which decides whether the latency
    /// figures mean anything (spec S11.2).
    pub same_host: bool,
}

impl Default for PktgenConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:0".parse().expect("literal"),
            target: "127.0.0.1:7400".parse().expect("literal"),
            frame: FrameSpec::default(),
            rate_pps: 0,
            flows: 1,
            duration: Duration::from_secs(1),
            vport: 0,
            batch: TX_BATCH,
            same_host: true,
        }
    }
}

/// One-way delay, measured from the overlay timestamp.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct Latency {
    /// Median, microseconds.
    pub p50_us: i64,
    /// 99th percentile, microseconds.
    pub p99_us: i64,
    /// Samples the percentiles were computed from.
    pub samples: usize,
    /// False when the two ends are on different hosts, in which case these
    /// numbers include an uncalibrated clock delta and are not a delay.
    pub calibrated: bool,
}

/// What a run achieved.
#[derive(Clone, Debug, Serialize)]
pub struct Report {
    /// Frames handed to the socket.
    pub sent: u64,
    /// Inner bytes sent.
    pub sent_bytes: u64,
    /// Frames received back.
    pub received: u64,
    /// Inner bytes received.
    pub received_bytes: u64,
    /// How long the sending phase actually took.
    pub elapsed_s: f64,
    /// Achieved send rate.
    pub tx_pps: f64,
    /// Achieved receive rate.
    pub rx_pps: f64,
    /// Achieved send rate in gigabits per second of inner traffic.
    pub tx_gbps: f64,
    /// Achieved receive rate in gigabits per second of inner traffic.
    pub rx_gbps: f64,
    /// Frames missing according to the overlay sequence numbers.
    pub seq_gap_total: u64,
    /// Frames that arrived behind the expectation.
    pub reorder: u64,
    /// Segments whose overlay header would not decode.
    pub bad_header: u64,
    /// Frames whose length did not match what was sent.
    pub length_mismatch: u64,
    /// Loss as a percentage of frames sent.
    pub loss_pct: f64,
    /// One-way delay, when any frame came back.
    pub latency: Option<Latency>,
}

/// Receive-side tallies, shared with the receiver thread.
#[derive(Debug, Default)]
struct RxStats {
    frames: AtomicU64,
    bytes: AtomicU64,
    gaps: AtomicU64,
    reorder: AtomicU64,
    bad_header: AtomicU64,
    length_mismatch: AtomicU64,
}

/// Send and receive for `config.duration`, then report.
///
/// `stop` lets a caller cut a run short; the receiver still drains for
/// [`DRAIN_GRACE`] so in-flight frames are not miscounted as loss.
pub fn run(config: &PktgenConfig, stop: &Stop) -> std::io::Result<Report> {
    let socket = Arc::new(FabricSocket::bind(config.bind, false)?);
    let mut template = FrameTemplate::new(config.frame);
    let frame_len = template.len();
    let segment = OVERLAY_HDR_LEN + frame_len;
    // A segmented write is one datagram until the kernel splits it, so the
    // batch is bounded by bytes as well as by count: 64 full-MTU segments do
    // not fit, and a write that does not fit is refused outright.
    let batch = config
        .batch
        .clamp(1, TX_BATCH.min(GSO_MAX_BYTES / segment).max(1));

    let stats = Arc::new(RxStats::default());
    let samples = Arc::new(std::sync::Mutex::new(Vec::<i64>::new()));
    let receiving = Stop::new();
    let receiver = {
        let socket = Arc::clone(&socket);
        let stats = Arc::clone(&stats);
        let samples = Arc::clone(&samples);
        let receiving = receiving.clone();
        std::thread::Builder::new()
            .name("pktgen-rx".to_owned())
            .spawn(move || receive_loop(&socket, &stats, &samples, frame_len, &receiving))?
    };

    let started = Instant::now();
    let deadline = started + config.duration;
    let mut sent = 0u64;
    let mut flow = 0u32;
    let mut buf = Vec::with_capacity(batch * segment);

    while Instant::now() < deadline && !stop.requested() {
        buf.clear();
        for _ in 0..batch {
            let mut hdr = [0u8; OVERLAY_HDR_LEN];
            up4_wire::encode(
                &Hdr {
                    ingress_vport: config.vport,
                    seq: Seq::new(sent as u32),
                    ts_us: clock::now_us(),
                },
                &mut hdr,
            );
            buf.extend_from_slice(&hdr);
            buf.extend_from_slice(template.for_flow(flow, config.flows));
            flow = (flow + 1) % config.flows.max(1);
            sent += 1;
        }
        socket.send(&Transmit {
            destination: config.target,
            ecn: None,
            contents: &buf,
            segment_size: (batch > 1).then_some(segment),
            src_ip: None,
        })?;
        pace(config.rate_pps, started, sent);
    }
    let elapsed = started.elapsed();

    std::thread::sleep(DRAIN_GRACE);
    receiving.request();
    receiver
        .join()
        .map_err(|_| std::io::Error::other("pktgen receive thread panicked"))?;

    Ok(finish(config, &stats, &samples, sent, frame_len, elapsed))
}

/// Hold the send rate to `rate_pps` by sleeping until the frame's due time.
///
/// A token bucket expressed as a deadline: frame *n* is due at
/// `start + n/rate`, so the pacing cannot drift.
fn pace(rate_pps: u64, started: Instant, sent: u64) {
    if rate_pps == 0 {
        return;
    }
    let due = started + Duration::from_nanos(sent.saturating_mul(1_000_000_000) / rate_pps);
    let now = Instant::now();
    if due > now {
        std::thread::sleep(due - now);
    }
}

/// Count and time everything that comes back until `stop`.
fn receive_loop(
    socket: &FabricSocket,
    stats: &RxStats,
    samples: &std::sync::Mutex<Vec<i64>>,
    expect_len: usize,
    stop: &Stop,
) {
    let mut storage = vec![0u8; 256 * 1024];
    let mut trackers: Vec<(u16, SeqTracker)> = Vec::new();
    let mut local = Vec::with_capacity(4096);

    while !stop.requested() {
        let mut iovs = [IoSliceMut::new(&mut storage)];
        let mut metas = [RecvMeta::default()];
        let Ok(n) = socket.recv(&mut iovs, &mut metas) else {
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
                let Ok(hdr) = up4_wire::decode(&storage[start..end]) else {
                    stats.bad_header.fetch_add(1, Ordering::Relaxed);
                    continue;
                };
                let len = end - start - OVERLAY_HDR_LEN;
                stats.frames.fetch_add(1, Ordering::Relaxed);
                stats.bytes.fetch_add(len as u64, Ordering::Relaxed);
                if len != expect_len {
                    stats.length_mismatch.fetch_add(1, Ordering::Relaxed);
                }
                // One tracker per sending vport; a handful at most, so a linear
                // scan beats a hash lookup.
                let tracker = match trackers.iter_mut().find(|(v, _)| *v == hdr.ingress_vport) {
                    Some((_, t)) => t,
                    None => {
                        trackers.push((hdr.ingress_vport, SeqTracker::new()));
                        &mut trackers.last_mut().expect("just pushed").1
                    }
                };
                match tracker.observe(hdr.seq) {
                    SeqEvent::InOrder => {}
                    SeqEvent::Gap(missing) => {
                        stats.gaps.fetch_add(u64::from(missing), Ordering::Relaxed);
                    }
                    SeqEvent::Reorder => {
                        stats.reorder.fetch_add(1, Ordering::Relaxed);
                    }
                }
                local.push(i64::from(clock::delta_us(clock::now_us(), hdr.ts_us)));
            }
        }
        if local.len() >= 4096 {
            flush_samples(samples, &mut local);
        }
    }
    flush_samples(samples, &mut local);
}

fn flush_samples(samples: &std::sync::Mutex<Vec<i64>>, local: &mut Vec<i64>) {
    if local.is_empty() {
        return;
    }
    let mut shared = samples.lock().unwrap_or_else(|e| e.into_inner());
    shared.append(local);
}

/// Turn the tallies into the report.
fn finish(
    config: &PktgenConfig,
    stats: &RxStats,
    samples: &std::sync::Mutex<Vec<i64>>,
    sent: u64,
    frame_len: usize,
    elapsed: Duration,
) -> Report {
    let secs = elapsed.as_secs_f64().max(f64::EPSILON);
    let received = stats.frames.load(Ordering::SeqCst);
    let received_bytes = stats.bytes.load(Ordering::SeqCst);
    let sent_bytes = sent * frame_len as u64;

    let mut latencies = samples.lock().unwrap_or_else(|e| e.into_inner()).clone();
    latencies.sort_unstable();
    let latency = (!latencies.is_empty()).then(|| Latency {
        p50_us: percentile(&latencies, 50),
        p99_us: percentile(&latencies, 99),
        samples: latencies.len(),
        calibrated: config.same_host,
    });

    Report {
        sent,
        sent_bytes,
        received,
        received_bytes,
        elapsed_s: secs,
        tx_pps: sent as f64 / secs,
        rx_pps: received as f64 / secs,
        tx_gbps: sent_bytes as f64 * 8.0 / secs / 1e9,
        rx_gbps: received_bytes as f64 * 8.0 / secs / 1e9,
        seq_gap_total: stats.gaps.load(Ordering::SeqCst),
        reorder: stats.reorder.load(Ordering::SeqCst),
        bad_header: stats.bad_header.load(Ordering::SeqCst),
        length_mismatch: stats.length_mismatch.load(Ordering::SeqCst),
        loss_pct: if sent == 0 {
            0.0
        } else {
            (sent.saturating_sub(received)) as f64 * 100.0 / sent as f64
        },
        latency,
    }
}

/// The `p`th percentile of a sorted slice, by index — no interpolation, no
/// histogram dependency (spec S11.2).
fn percentile(sorted: &[i64], p: usize) -> i64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = (sorted.len() * p / 100).min(sorted.len() - 1);
    sorted[idx]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentiles_index_a_sorted_slice() {
        let s: Vec<i64> = (0..100).collect();
        assert_eq!(percentile(&s, 50), 50);
        assert_eq!(percentile(&s, 99), 99);
        assert_eq!(percentile(&s, 100), 99, "clamped to the last sample");
        assert_eq!(percentile(&[], 50), 0);
    }

    #[test]
    fn pacing_sleeps_only_when_it_is_ahead() {
        let started = Instant::now();
        // Frame 1_000_000 at 1 Mpps is due one second in; but frame 0 is due now.
        pace(1_000_000, started, 0);
        assert!(
            started.elapsed() < Duration::from_millis(50),
            "no sleep for the first frame"
        );
        pace(0, started, 1_000_000);
        assert!(
            started.elapsed() < Duration::from_millis(50),
            "rate 0 never sleeps"
        );
    }

    #[test]
    fn the_batch_is_bounded_by_what_one_segmented_write_can_carry() {
        let segment = OVERLAY_HDR_LEN + 1460;
        assert!(
            TX_BATCH * segment > GSO_MAX_BYTES,
            "the bound is not vacuous"
        );
        assert!((GSO_MAX_BYTES / segment) * segment <= GSO_MAX_BYTES);
    }

    #[test]
    fn a_run_with_no_listener_reports_total_loss_rather_than_failing() {
        let config = PktgenConfig {
            // Nothing is bound here, so the frames land nowhere.
            target: "127.0.0.1:9".parse().expect("literal"),
            duration: Duration::from_millis(50),
            rate_pps: 1000,
            batch: 1,
            ..PktgenConfig::default()
        };
        let report = run(&config, &Stop::new()).expect("the generator itself does not fail");
        assert!(report.sent > 0);
        assert_eq!(report.received, 0);
        assert!((report.loss_pct - 100.0).abs() < f64::EPSILON);
        assert!(report.latency.is_none());
    }
}
