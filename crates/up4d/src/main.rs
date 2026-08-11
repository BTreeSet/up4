//! `up4d`: one up4 node (spec S2, S12, S15).
//!
//! This binary is wiring and lifecycle, nothing else. It has no forwarding
//! logic (spec S1.3), no protocol of its own, and no policy that is not either
//! in the configuration or in the loaded pipeline. What it does own is the
//! order things happen in:
//!
//! 1. block terminating signals **before any thread exists**, so none can be
//!    killed out from under a final snapshot;
//! 2. probe the host and log the banner (spec S11.1);
//! 3. load and validate the configuration, reporting *every* violation (S5);
//! 4. load the pipeline and any startup table batch;
//! 5. bind one socket per shard, spawn the shards, the control server, and the
//!    snapshot writer;
//! 6. wait; then stop rx, let each shard flush what it staged, write a final
//!    snapshot, and exit 0 (A6).

use clap::Parser;
use std::{
    path::PathBuf,
    process::ExitCode,
    sync::Arc,
    time::{Duration, Instant},
};
use tracing::{error, info, warn};
use up4_config::{Config, LoadError};
use up4_ctl::EntryBatch;
use up4_engine::catalog::{Program, Selection};
use up4_engine::{Pipeline, PipelineParams};
use up4_io::{FabricSocket, PuntQueue, Shard, ShardParams, Stop, clock, probe::Probe};
use up4_metrics::{Metrics, SnapshotWriter};

/// Exit code for a fatal startup error (spec S12).
const EXIT_STARTUP: u8 = 2;

#[derive(Parser)]
#[command(
    name = "up4d",
    about = "An unprivileged userspace P4 switch",
    version,
    max_term_width = 100
)]
struct Cli {
    /// Which backend executes the configured pipeline.
    ///
    /// Omitted means `native`. The three are interchangeable: same `.p4`, same
    /// tables, same `up4ctl` calls; they differ in provenance and cost, which
    /// `up4ctl info` reports rather than this help text claiming.
    #[arg(long, value_parser = ["native", "x4c", "ubpf"])]
    backend: Option<String>,

    /// Path to the node's TOML configuration (spec S5).
    #[arg(long, short, env = "UP4_CONFIG")]
    config: PathBuf,

    /// Install these table entries before the datapath starts.
    ///
    /// Same JSON format as `up4ctl table load`, so a topology and its routes
    /// can be brought up in one command.
    #[arg(long)]
    tables: Option<PathBuf>,

    /// Directory for `up4-metrics-<node>.jsonl` (spec S9).
    #[arg(long, default_value = ".")]
    metrics_dir: PathBuf,

    /// Validate the configuration and the table batch, then exit.
    #[arg(long)]
    check: bool,
}

/// One line describing what is loaded, for `up4ctl info`.
fn selection_summary(name: &str) -> String {
    Selection::all()
        .into_iter()
        .find(|s| s.name() == name)
        .map_or_else(String::new, |s| match s {
            Selection::P4 { program, backend } => {
                format!("{} [{}]", program.summary(), backend.name())
            }
            Selection::Oracle => "benchmark oracle (spec S7.4)".to_owned(),
        })
}

fn main() -> ExitCode {
    // Before anything else spawns a thread: threads inherit the signal mask,
    // and a thread that has not blocked SIGTERM dies on it (spec S12, A6).
    if let Err(e) = up4_io::signal::block_terminating_signals() {
        eprintln!("up4d: cannot block terminating signals: {e}");
        return ExitCode::from(EXIT_STARTUP);
    }
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    match run(&Cli::parse()) {
        Ok(code) => code,
        Err(e) => {
            error!("{e}");
            ExitCode::from(EXIT_STARTUP)
        }
    }
}

/// A startup failure, always fatal and always fully explained.
struct Fatal(String);

impl std::fmt::Display for Fatal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<std::io::Error> for Fatal {
    fn from(e: std::io::Error) -> Self {
        Self(e.to_string())
    }
}

fn run(cli: &Cli) -> Result<ExitCode, Fatal> {
    let started_us = clock::monotonic_us();

    // The banner is the first line, before the configuration is even read, so
    // a failed startup still tells you what host it failed on (spec S11.1).
    let peer_hint = first_peer(&cli.config);
    let probe = up4_io::probe(peer_hint);
    info!(banner = %serde_json::to_string(&probe).unwrap_or_else(|e| e.to_string()));
    for warning in &probe.warnings {
        warn!("probe: {warning}");
    }

    // A configuration names a *program*; the backend is a separate axis with
    // its own default (spec S7.2, `Selection`).
    let registry: Vec<&str> = Program::ALL.iter().map(|p| p.name()).collect();
    let config = Config::load(&cli.config, &registry).map_err(|e| match e {
        LoadError::Io { .. } => Fatal(e.to_string()),
        // Every violation, not the first (spec S5).
        LoadError::Invalid(errors) => Fatal(format!("{} in {}", errors, cli.config.display())),
    })?;
    echo_config(&config);

    let selection = Selection::parse(&config.node.pipeline, cli.backend.as_deref())
        .map_err(|e| Fatal(e.to_string()))?;
    // Total: `Selection` is closed and every variant is implemented, so there
    // is no "unknown pipeline" path left to handle here.
    let pipeline: Arc<dyn Pipeline> = Arc::from(up4_catalog::build(
        selection,
        &PipelineParams::new(config.vports.iter().map(|(_, v)| v.id.get())),
    ));
    info!(
        pipeline = pipeline.name(),
        tables = pipeline.tables().schemas().len(),
        "pipeline loaded"
    );

    if let Some(path) = &cli.tables {
        let count = load_tables(&*pipeline, path)?;
        info!(entries = count, file = %path.display(), "startup table batch installed");
    }

    if cli.check {
        info!("configuration and tables are valid");
        return Ok(ExitCode::SUCCESS);
    }

    serve(cli, config, pipeline, probe, started_us)
}

/// Bring up the datapath, the control channel, and the snapshot writer, then
/// wait for a stop and unwind in the order A6 requires.
fn serve(
    cli: &Cli,
    config: Config,
    pipeline: Arc<dyn Pipeline>,
    probe: Probe,
    started_us: u64,
) -> Result<ExitCode, Fatal> {
    let inner_mtu = config.inner_mtu();
    let topology = Arc::new(config.vports.clone());
    let metrics = Arc::new(Metrics::new(&config.node.id, &topology));
    let punt = config.punt.map(|_| Arc::new(PuntQueue::new(inner_mtu)));
    let stop = Stop::new();
    let threads = config.node.threads.get();

    // Bind every socket before spawning anything: a bind failure must be a
    // startup error, not a thread that dies after the node reports ready.
    let mut sockets = Vec::with_capacity(threads);
    for shard in 0..threads {
        let socket = FabricSocket::bind(config.node.bind, threads > 1).map_err(|e| {
            Fatal(format!(
                "shard {shard} cannot bind {}: {e}",
                config.node.bind
            ))
        })?;
        let caps = socket.caps();
        info!(
            shard,
            rcvbuf = caps.rcvbuf,
            sndbuf = caps.sndbuf,
            gro = caps.gro(),
            gso = caps.gso(),
            max_gso_segments = caps.max_gso_segments,
            gro_segments = caps.gro_segments,
            "socket ready"
        );
        sockets.push(socket);
    }

    let mut shards = Vec::with_capacity(threads);
    for (id, socket) in sockets.into_iter().enumerate() {
        let params = ShardParams {
            id,
            topology: Arc::clone(&topology),
            metrics: Arc::clone(&metrics),
            inner_mtu,
            punt: punt.clone(),
        };
        let mut shard = Shard::new(socket, pipeline.engine(), params);
        let stop = stop.clone();
        let pin = config.node.pin_cores.get(id).copied();
        shards.push(
            std::thread::Builder::new()
                .name(format!("up4-shard-{id}"))
                .spawn(move || {
                    if let Some(core) = pin {
                        // Pinning is best-effort by spec S5: a cgroup may
                        // simply not allow this core.
                        if core_affinity::set_for_current(core_affinity::CoreId { id: core }) {
                            info!(shard = id, core, "pinned");
                        } else {
                            warn!(shard = id, core, "could not pin; continuing unpinned");
                        }
                    }
                    if let Err(e) = shard.run(&stop) {
                        error!(shard = id, "datapath stopped: {e}");
                        stop.request();
                    }
                })
                .map_err(|e| Fatal(format!("cannot spawn shard {id}: {e}")))?,
        );
    }

    let ctl = up4_ctl::Server::bind(
        &config.node.ctl_socket,
        Arc::new(up4_ctl::Context {
            info: node_info(&config, &*pipeline, &probe),
            started_us,
            metrics: Arc::clone(&metrics),
            pipeline: Arc::clone(&pipeline),
            punt: punt.clone(),
            stop: stop.clone(),
        }),
    )
    .map_err(|e| {
        Fatal(format!(
            "control socket {}: {e}",
            config.node.ctl_socket.display()
        ))
    })?;
    let ctl_thread = {
        let stop = stop.clone();
        std::thread::Builder::new()
            .name("up4-ctl".to_owned())
            .spawn(move || {
                if let Err(e) = ctl.serve(&stop) {
                    error!("control channel stopped: {e}");
                }
                // The server owns its socket file and removes it here.
                drop(ctl);
            })
            .map_err(|e| Fatal(format!("cannot spawn the control thread: {e}")))?
    };

    let snapshots = config.node.metrics_interval.map(|interval| {
        spawn_snapshot_writer(
            &cli.metrics_dir,
            &config.node.id,
            Arc::clone(&metrics),
            interval,
            stop.clone(),
        )
    });

    let watcher = up4_io::signal::spawn_watcher(stop.clone())?;
    info!(
        node = config.node.id,
        ctl = %config.node.ctl_socket.display(),
        "up4d ready"
    );

    // Wait for a signal or a `shutdown` command. Polling a flag beats a
    // condvar here: the process has nothing else to do, and this keeps the
    // shutdown path identical for both sources.
    while !stop.requested() {
        std::thread::sleep(Duration::from_millis(50));
    }
    info!("stopping");

    // A6's order: rx stops, staged frames flush (each shard flushes as it
    // leaves its loop), then the final snapshot, then exit 0.
    for (id, shard) in shards.into_iter().enumerate() {
        if shard.join().is_err() {
            // Release builds abort on a panicking thread (spec S12), so this
            // is reachable only in a debug build, where saying so beats a
            // silent half-alive switch just as much.
            error!(shard = id, "shard thread panicked");
        }
    }
    if ctl_thread.join().is_err() {
        error!("control thread panicked");
    }
    if let Some(writer) = snapshots
        && writer.join().is_err()
    {
        error!("snapshot thread panicked");
    }
    // The watcher is still parked in `sigwait` if we were stopped by a control
    // command; it is a daemon thread with no state to lose.
    drop(watcher);

    let snapshot = metrics.snapshot(clock::wall_us());
    info!(
        counters = %serde_json::to_string(&snapshot).unwrap_or_else(|e| e.to_string()),
        "final snapshot"
    );
    match write_final_snapshot(cli, &config, &snapshot) {
        Ok(Some(path)) => info!(path = %path.display(), "final snapshot appended"),
        Ok(None) => {}
        Err(e) => warn!("could not append the final snapshot: {e}"),
    }
    Ok(ExitCode::SUCCESS)
}

/// Append the last snapshot to the JSONL file, if snapshots are enabled.
fn write_final_snapshot(
    cli: &Cli,
    config: &Config,
    snapshot: &up4_metrics::Snapshot,
) -> std::io::Result<Option<PathBuf>> {
    if config.node.metrics_interval.is_none() {
        return Ok(None);
    }
    let mut writer = SnapshotWriter::open(&cli.metrics_dir, &config.node.id)?;
    writer.append(snapshot)?;
    Ok(Some(writer.path().to_owned()))
}

/// The periodic counter snapshot thread (spec S9).
fn spawn_snapshot_writer(
    dir: &std::path::Path,
    node: &str,
    metrics: Arc<Metrics>,
    interval: Duration,
    stop: Stop,
) -> std::thread::JoinHandle<()> {
    let mut writer = match SnapshotWriter::open(dir, node) {
        Ok(w) => {
            info!(path = %w.path().display(), interval_s = interval.as_secs(), "writing snapshots");
            Some(w)
        }
        Err(e) => {
            warn!("counter snapshots disabled: {e}");
            None
        }
    };
    std::thread::spawn(move || {
        let mut next = Instant::now() + interval;
        while !stop.requested() {
            std::thread::sleep(Duration::from_millis(50));
            if Instant::now() < next {
                continue;
            }
            next += interval;
            if let Some(w) = &mut writer
                && let Err(e) = w.append(&metrics.snapshot(clock::wall_us()))
            {
                warn!("snapshot write failed: {e}");
            }
        }
    })
}

/// Install a startup table batch through the same path `up4ctl` uses, so the
/// file format and every refusal message are identical.
fn load_tables(pipeline: &dyn Pipeline, path: &std::path::Path) -> Result<usize, Fatal> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| Fatal(format!("cannot read {}: {e}", path.display())))?;
    let batch: EntryBatch =
        serde_json::from_str(&text).map_err(|e| Fatal(format!("{}: {e}", path.display())))?;
    up4_ctl::apply_entries(pipeline.tables(), &batch.into_entries())
        .map_err(|message| Fatal(format!("{}: {message}", path.display())))
}

/// Read just enough of the configuration to pick a probe peer, before the real
/// parse. A failure here is not an error: the probe simply reports no route.
fn first_peer(config: &std::path::Path) -> Option<std::net::IpAddr> {
    let text = std::fs::read_to_string(config).ok()?;
    text.lines()
        .filter_map(|l| l.split_once('='))
        .filter(|(k, _)| k.trim() == "peer")
        .filter_map(|(_, v)| {
            v.trim()
                .trim_matches('"')
                .parse::<std::net::SocketAddr>()
                .ok()
        })
        .map(|a| a.ip())
        .next()
}

/// Echo the configuration as understood, not as written (spec S12).
fn echo_config(config: &Config) {
    info!(
        node = config.node.id,
        bind = %config.node.bind,
        fabric = config.node.fabric.as_str(),
        inner_mtu = config.inner_mtu(),
        pipeline = config.node.pipeline,
        threads = config.node.threads.get(),
        vports = config.vports.len(),
        punt = config.punt.is_some(),
        metrics_interval_s = config.node.metrics_interval.map_or(0, |d| d.as_secs()),
        "configuration"
    );
    for (_, vport) in config.vports.iter() {
        info!(vport = vport.id.get(), peer = %vport.peer, "vport");
    }
}

/// The static half of the `info` reply.
fn node_info(config: &Config, pipeline: &dyn Pipeline, probe: &Probe) -> up4_ctl::Info {
    up4_ctl::Info {
        node: config.node.id.clone(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        pipeline: pipeline.name().to_owned(),
        pipeline_summary: selection_summary(pipeline.name()),
        uptime_s: 0,
        threads: config.node.threads.get(),
        fabric: config.node.fabric.as_str().to_owned(),
        inner_mtu: config.inner_mtu(),
        bind: config.node.bind.to_string(),
        punt_enabled: config.punt.is_some(),
        vports: config
            .vports
            .iter()
            .map(|(_, v)| up4_ctl::VportInfo {
                id: v.id.get(),
                peer: v.peer.to_string(),
            })
            .collect(),
        probe: serde_json::to_value(probe).unwrap_or(serde_json::Value::Null),
    }
}
