//! `probe`: what this host will let up4 do (spec S11.1).
//!
//! Prints one JSON object and exits. `up4d` runs the same probe at startup and
//! logs it as its banner, so a result attached to an experiment and a result
//! taken by hand are the same document.

use clap::Parser;
use std::net::IpAddr;

#[derive(Parser)]
#[command(
    name = "probe",
    about = "Report this host's UDP offload and buffer limits",
    version
)]
struct Cli {
    /// Peer address whose route MTU to report.
    #[arg(long)]
    peer: Option<IpAddr>,

    /// Print with indentation.
    #[arg(long)]
    pretty: bool,
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    let probe = up4_io::probe(cli.peer);
    let rendered = if cli.pretty {
        serde_json::to_string_pretty(&probe)
    } else {
        serde_json::to_string(&probe)
    };
    match rendered {
        Ok(text) => {
            println!("{text}");
            std::process::ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("probe: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}
