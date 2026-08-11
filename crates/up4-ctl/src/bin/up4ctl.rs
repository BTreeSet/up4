//! `up4ctl` — the operator's side of the control channel (spec S8.2).
//!
//! A thin 1:1 mapping onto the protocol: every subcommand is one request, and
//! `--json` prints the reply verbatim so scripts never parse the human output.
//! The human output is the default because the primary user of this tool is
//! someone running an experiment.

use clap::{Args, Parser, Subcommand};
use std::{path::PathBuf, process::ExitCode};
use up4_ctl::{
    Client, EntryBatch, EntrySpec, Params, Request, Response, protocol::PuntedFrame,
    server::PUNT_DRAIN_MAX,
};

#[derive(Parser)]
#[command(
    name = "up4ctl",
    about = "Control an up4 node over its unix socket",
    version,
    max_term_width = 100
)]
struct Cli {
    /// Path of the node's control socket (`node.ctl_socket` in up4.toml).
    #[arg(long, short, env = "UP4_CTL_SOCKET", default_value = "/tmp/up4.sock")]
    socket: PathBuf,

    /// Print the reply as JSON instead of formatting it.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Check that the node is alive.
    Ping,
    /// Show build, pipeline, topology, and startup probe.
    Info,
    /// Snapshot every counter.
    Counters,
    /// Show each table's key and actions, straight from the P4 program.
    Tables,
    /// Read and write match-action tables.
    #[command(subcommand)]
    Table(TableCommand),
    /// Take punted frames from the queue.
    Punt(PuntArgs),
    /// Stop the node gracefully: flush, snapshot, exit 0.
    Shutdown,
}

#[derive(Subcommand)]
enum TableCommand {
    /// List installed entries and the default action.
    Dump {
        /// Table name; see `up4ctl tables`.
        table: String,
    },
    /// Install or replace one entry.
    ///
    /// Parameters may be positional (`1 aa:bb:cc:dd:ee:01`) or named
    /// (`port=1 dmac=aa:bb:cc:dd:ee:01`).
    Add {
        /// Table name.
        table: String,
        /// Key, in the table's syntax (`10.0.0.0/24`, `aa:bb:cc:dd:ee:01`).
        key: String,
        /// Action name.
        action: String,
        /// Action parameters.
        params: Vec<String>,
    },
    /// Remove one entry.
    Del {
        /// Table name.
        table: String,
        /// Key to remove.
        key: String,
    },
    /// Replace the action taken when nothing matches.
    Default {
        /// Table name.
        table: String,
        /// Action name.
        action: String,
        /// Action parameters.
        params: Vec<String>,
    },
    /// Remove every entry from a table.
    Clear {
        /// Table name.
        table: String,
    },
    /// Install a batch of entries from a JSON file.
    ///
    /// The file is either `{"entries": [...]}` or a bare array, where each
    /// entry is `{"table":..., "key":..., "action":..., "params":...}` and
    /// `params` is a list or an object.
    Load {
        /// Path to the batch file.
        file: PathBuf,
    },
}

#[derive(Args)]
struct PuntArgs {
    /// Frames to take (capped by the node at its drain limit).
    #[arg(long, default_value_t = PUNT_DRAIN_MAX)]
    max: usize,
    /// Keep draining until the queue is empty.
    #[arg(long)]
    all: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("up4ctl: {e}");
            ExitCode::from(2)
        }
    }
}

fn run(cli: &Cli) -> std::io::Result<ExitCode> {
    let mut client = Client::connect(&cli.socket)?;
    let request = match &cli.command {
        Command::Ping => Request::Ping,
        Command::Info => Request::Info,
        Command::Counters => Request::Counters,
        Command::Tables => Request::Tables,
        Command::Shutdown => Request::Shutdown,
        Command::Punt(args) => return drain(&mut client, args, cli.json),
        Command::Table(TableCommand::Dump { table }) => Request::TableDump {
            table: table.clone(),
        },
        Command::Table(TableCommand::Del { table, key }) => Request::TableDel {
            table: table.clone(),
            key: key.clone(),
        },
        Command::Table(TableCommand::Clear { table }) => Request::TableClear {
            table: table.clone(),
        },
        Command::Table(TableCommand::Add {
            table,
            key,
            action,
            params,
        }) => Request::TableAdd {
            entries: vec![EntrySpec {
                table: table.clone(),
                key: key.clone(),
                action: action.clone(),
                params: Params::from_args(params),
            }],
        },
        Command::Table(TableCommand::Default {
            table,
            action,
            params,
        }) => Request::TableSetDefault {
            table: table.clone(),
            action: action.clone(),
            params: Params::from_args(params),
        },
        Command::Table(TableCommand::Load { file }) => {
            let text = std::fs::read_to_string(file).map_err(|e| {
                std::io::Error::new(e.kind(), format!("cannot read {}: {e}", file.display()))
            })?;
            let batch: EntryBatch = serde_json::from_str(&text).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("{}: {e}", file.display()),
                )
            })?;
            Request::TableAdd {
                entries: batch.into_entries(),
            }
        }
    };
    let response = client.call(&request)?;
    Ok(report(&response, cli.json))
}

/// `punt drain`, optionally repeating until the queue is empty.
fn drain(client: &mut Client, args: &PuntArgs, json: bool) -> std::io::Result<ExitCode> {
    let mut all = Vec::new();
    loop {
        let response = client.call(&Request::PuntDrain { max: args.max })?;
        let Response::Punted { frames, remaining } = response else {
            return Ok(report(&response, json));
        };
        let done = frames.is_empty() || !args.all || remaining == 0;
        all.extend(frames);
        if done {
            let response = Response::Punted {
                frames: all,
                remaining,
            };
            return Ok(report(&response, json));
        }
    }
}

/// Print a reply and choose the exit code: 0 for an answer, 1 for a refusal.
fn report(response: &Response, json: bool) -> ExitCode {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(response)
                .unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
        );
        return match response {
            Response::Error { .. } => ExitCode::FAILURE,
            _ => ExitCode::SUCCESS,
        };
    }
    match response {
        Response::Pong => println!("pong"),
        Response::ShuttingDown => println!("shutting down"),
        Response::Applied { count } => println!("{count} entr{} applied", plural(*count)),
        Response::Error { message } => {
            eprintln!("error: {message}");
            return ExitCode::FAILURE;
        }
        Response::Info(info) => print_info(info),
        Response::Counters(snapshot) => print_counters(snapshot),
        Response::Tables { tables } => print_schemas(tables),
        Response::Entries { entries, default } => {
            for e in entries {
                println!("{:<20} {} {}", e.key, e.action, params_of(e));
            }
            println!(
                "{:<20} {} {}   (default)",
                "*",
                default.action,
                params_of(default)
            );
            println!("\n{} entr{}", entries.len(), plural(entries.len()));
        }
        Response::Punted { frames, remaining } => print_punted(frames, *remaining),
    }
    ExitCode::SUCCESS
}

fn plural(n: usize) -> &'static str {
    if n == 1 { "y" } else { "ies" }
}

fn params_of(entry: &up4_engine::EntryDesc) -> String {
    entry
        .params
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn print_info(info: &up4_ctl::Info) {
    println!("node       {}", info.node);
    println!("version    up4 {}", info.version);
    println!("pipeline   {} — {}", info.pipeline, info.pipeline_summary);
    println!("uptime     {} s", info.uptime_s);
    println!(
        "bind       {} ({} shard{})",
        info.bind,
        info.threads,
        if info.threads == 1 { "" } else { "s" }
    );
    println!("fabric     {} (inner MTU {})", info.fabric, info.inner_mtu);
    println!(
        "punt       {}",
        if info.punt_enabled {
            "enabled"
        } else {
            "not configured"
        }
    );
    println!("vports");
    for v in &info.vports {
        println!("  {:<5} -> {}", v.id, v.peer);
    }
    if let Some(warnings) = info.probe.get("warnings").and_then(|w| w.as_array())
        && !warnings.is_empty()
    {
        println!("probe warnings");
        for w in warnings {
            println!("  - {}", w.as_str().unwrap_or_default());
        }
    }
}

fn print_counters(snapshot: &up4_metrics::Snapshot) {
    println!("node {} @ {} us", snapshot.node, snapshot.ts_us);
    for (name, value) in &snapshot.counters {
        println!("  {name:<24} {value}");
    }
    println!("  {:<24} {}", "harness_drops (sum)", snapshot.harness_drops);
    for vport in &snapshot.vports {
        println!("vport {}", vport.id);
        for (name, value) in &vport.counters {
            println!("  {name:<24} {value}");
        }
    }
    for (name, hist) in &snapshot.histograms {
        let cells: Vec<String> = hist
            .buckets
            .iter()
            .map(|b| match b.le {
                Some(le) => format!("<={le}:{}", b.count),
                None => format!(">64:{}", b.count),
            })
            .collect();
        println!("{name:<24} {}", cells.join(" "));
    }
}

fn print_schemas(schemas: &[up4_engine::SchemaDesc]) {
    if schemas.is_empty() {
        println!("this pipeline has no tables");
        return;
    }
    for s in schemas {
        let (kind, value) = match s.key {
            up4_engine::KeyKind::Exact(k) => ("exact", k),
            up4_engine::KeyKind::Lpm(k) => ("lpm", k),
        };
        println!("table {}", s.name);
        println!("  key    {} : {kind}   ({})", s.key_field, value.syntax());
        for a in &s.actions {
            let params: Vec<String> = a
                .params
                .iter()
                .map(|p| format!("{}: {}", p.name, p.kind.syntax()))
                .collect();
            println!("  action {}({})", a.name, params.join(", "));
        }
    }
}

fn print_punted(frames: &[PuntedFrame], remaining: usize) {
    for f in frames {
        println!(
            "vport {} @ {} us  {}",
            f.ingress_vport, f.rx_ts_us, f.frame_b64
        );
    }
    println!("\n{} frame(s), {remaining} still queued", frames.len());
}
