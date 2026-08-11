//! `pktgen` — offered load, and what actually came back (spec S11.2).
//!
//! The generator binds an address that must appear as a `peer` in the target
//! node's topology; otherwise the node counts `rx_unknown_peer` and the run
//! reports total loss, which is the correct answer to a misconfigured
//! experiment.

use clap::Parser;
use std::{
    net::{Ipv4Addr, SocketAddr},
    process::ExitCode,
    time::Duration,
};
use up4_engine::MacAddr;
use up4_io::Stop;
use up4_tools::{PktgenConfig, frame::FrameSpec};

#[derive(Parser)]
#[command(
    name = "pktgen",
    about = "Drive an up4 node with synthetic traffic",
    version,
    max_term_width = 100
)]
struct Cli {
    /// Address to send from; must be a configured peer of the target node.
    #[arg(long)]
    bind: SocketAddr,

    /// The node's fabric address (`node.bind` in its up4.toml).
    #[arg(long)]
    target: SocketAddr,

    /// Inner frame size in bytes.
    #[arg(long, default_value_t = 1460)]
    frame_size: usize,

    /// Frames per second; 0 sends as fast as the socket accepts.
    #[arg(long, default_value_t = 0)]
    rate_pps: u64,

    /// Distinct inner flows to rotate through.
    #[arg(long, default_value_t = 1)]
    flows: u32,

    /// Seconds to send for.
    #[arg(long, default_value_t = 10)]
    duration: u64,

    /// Vport id to claim in the overlay header.
    #[arg(long, default_value_t = 0)]
    vport: u16,

    /// Segments per send; 1 disables GSO batching.
    #[arg(long, default_value_t = 64)]
    batch: usize,

    /// Inner destination MAC — the key `l2fwd` matches on.
    #[arg(long, default_value = "02:00:00:00:00:02")]
    dst_mac: String,

    /// Inner source MAC.
    #[arg(long, default_value = "02:00:00:00:00:01")]
    src_mac: String,

    /// Inner destination IPv4 — the route `l3fwd` matches on.
    #[arg(long, default_value = "10.0.2.1")]
    dst_ip: Ipv4Addr,

    /// Inner source IPv4; flows vary its low octets.
    #[arg(long, default_value = "10.0.1.1")]
    src_ip: Ipv4Addr,

    /// The node is on another host, so latency is an uncalibrated clock delta.
    #[arg(long)]
    cross_host: bool,

    /// Print the report as JSON.
    #[arg(long)]
    json: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let (Ok(src_mac), Ok(dst_mac)) = (
        cli.src_mac.parse::<MacAddr>(),
        cli.dst_mac.parse::<MacAddr>(),
    ) else {
        eprintln!("pktgen: --src-mac and --dst-mac must look like aa:bb:cc:dd:ee:ff");
        return ExitCode::from(2);
    };

    let config = PktgenConfig {
        bind: cli.bind,
        target: cli.target,
        frame: FrameSpec {
            src_mac,
            dst_mac,
            src_ip: cli.src_ip,
            dst_ip: cli.dst_ip,
            len: cli.frame_size,
            ..FrameSpec::default()
        },
        rate_pps: cli.rate_pps,
        flows: cli.flows.max(1),
        duration: Duration::from_secs(cli.duration),
        vport: cli.vport,
        batch: cli.batch,
        same_host: !cli.cross_host,
    };

    match up4_tools::run(&config, &Stop::new()) {
        Err(e) => {
            eprintln!("pktgen: {e}");
            ExitCode::from(2)
        }
        Ok(report) => {
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).unwrap_or_else(|e| e.to_string())
                );
            } else {
                print_report(&report);
            }
            ExitCode::SUCCESS
        }
    }
}

fn print_report(r: &up4_tools::Report) {
    println!(
        "sent      {:>12} frames  {:>8.3} Mpps  {:>7.3} Gbps",
        r.sent,
        r.tx_pps / 1e6,
        r.tx_gbps
    );
    println!(
        "received  {:>12} frames  {:>8.3} Mpps  {:>7.3} Gbps",
        r.received,
        r.rx_pps / 1e6,
        r.rx_gbps
    );
    println!(
        "loss      {:>12.4} %  ({} missing by sequence)",
        r.loss_pct, r.seq_gap_total
    );
    println!(
        "reorder   {:>12}  bad_header {}  length_mismatch {}",
        r.reorder, r.bad_header, r.length_mismatch
    );
    match &r.latency {
        None => println!("latency   no frames returned"),
        Some(l) => {
            let note = if l.calibrated {
                ""
            } else {
                "  (uncalibrated clock delta)"
            };
            println!(
                "latency   p50 {} us  p99 {} us  n={}{note}",
                l.p50_us, l.p99_us, l.samples
            );
        }
    }
}
