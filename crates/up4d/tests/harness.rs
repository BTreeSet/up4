//! Shared fixtures for the end-to-end tests: temporary directories, free
//! ports, and a supervised `up4d` process.
//!
//! Compiled into each test binary that declares `mod harness;`, so anything
//! unused by one of them is allowed to be dead there.
#![allow(dead_code)]

use std::{
    net::{SocketAddr, UdpSocket},
    path::{Path, PathBuf},
    process::{Child, Command},
    time::{Duration, Instant},
};
use up4_ctl::{Client, Request, Response};

/// How long a node has to come up before a test gives up on it.
const READY_TIMEOUT: Duration = Duration::from_secs(20);

/// Serializes the end-to-end tests.
///
/// Two reasons, both real: loopback ports are reserved and then handed to a
/// child process, so overlapping fixtures could be given the same port; and a
/// throughput assertion measured while three other fixtures are saturating the
/// same four cores is measuring the test runner, not up4.
static EXCLUSIVE: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Take the end-to-end lock for the rest of the test.
pub fn exclusive() -> std::sync::MutexGuard<'static, ()> {
    EXCLUSIVE.lock().unwrap_or_else(|e| e.into_inner())
}

/// A directory that removes itself, so a failed run leaves nothing behind but
/// its output.
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "up4-e2e-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create the test directory");
        Self(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    pub fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    pub fn write(&self, name: &str, contents: &str) -> PathBuf {
        let path = self.join(name);
        std::fs::write(&path, contents).expect("write a test file");
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Reserve `n` loopback UDP ports.
///
/// The sockets stay bound until the caller drops the guard, so two tests
/// running in parallel cannot be handed the same port.
pub struct Ports {
    held: Vec<UdpSocket>,
    addrs: Vec<SocketAddr>,
}

impl Ports {
    pub fn reserve(n: usize) -> Self {
        let held: Vec<UdpSocket> = (0..n)
            .map(|_| UdpSocket::bind("127.0.0.1:0").expect("reserve a loopback port"))
            .collect();
        let addrs = held
            .iter()
            .map(|s| s.local_addr().expect("bound"))
            .collect();
        Self { held, addrs }
    }

    pub fn addr(&self, i: usize) -> SocketAddr {
        self.addrs[i]
    }

    /// Release the ports so the nodes and generators can take them.
    pub fn release(&mut self) {
        self.held.clear();
    }
}

/// How a node should be configured.
pub struct NodeSpec<'a> {
    pub id: &'a str,
    pub bind: SocketAddr,
    pub pipeline: &'a str,
    /// `(vport id, peer)` pairs.
    pub vports: &'a [(u16, SocketAddr)],
    pub punt: bool,
    pub metrics_interval_s: u64,
    /// Entries to install before the datapath starts, as a JSON batch.
    pub tables: Option<String>,
}

impl NodeSpec<'_> {
    fn toml(&self, ctl: &Path) -> String {
        let mut s = format!(
            "[node]\nid = \"{}\"\nbind = \"{}\"\npipeline = \"{}\"\nthreads = 1\n\
             ctl_socket = \"{}\"\nmetrics_interval_s = {}\n",
            self.id,
            self.bind,
            self.pipeline,
            ctl.display(),
            self.metrics_interval_s
        );
        for (id, peer) in self.vports {
            s.push_str(&format!("\n[[vport]]\nid = {id}\npeer = \"{peer}\"\n"));
        }
        if self.punt {
            s.push_str("\n[punt]\nvport = 65535\n");
        }
        s
    }
}

/// A running `up4d`.
pub struct Node {
    child: Child,
    ctl: PathBuf,
    id: String,
}

impl Node {
    /// Write the configuration, start the process, and wait for it to answer.
    pub fn start(dir: &TempDir, spec: &NodeSpec<'_>) -> Self {
        let ctl = dir.join(&format!("{}.sock", spec.id));
        let config = dir.write(&format!("{}.toml", spec.id), &spec.toml(&ctl));
        let mut command = Command::new(env!("CARGO_BIN_EXE_up4d"));
        command
            .arg("--config")
            .arg(&config)
            .arg("--metrics-dir")
            .arg(dir.path())
            .env("RUST_LOG", "up4d=info,up4_io=warn,up4_ctl=warn");
        if let Some(tables) = &spec.tables {
            let path = dir.write(&format!("{}-tables.json", spec.id), tables);
            command.arg("--tables").arg(path);
        }
        let child = command.spawn().expect("spawn up4d");
        let node = Self {
            child,
            ctl,
            id: spec.id.to_owned(),
        };
        node.await_ready();
        node
    }

    fn await_ready(&self) {
        let deadline = Instant::now() + READY_TIMEOUT;
        while Instant::now() < deadline {
            if let Ok(mut client) = Client::connect(&self.ctl)
                && client
                    .call(&Request::Ping)
                    .is_ok_and(|r| r == Response::Pong)
            {
                return;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        panic!(
            "node {} did not become ready within {READY_TIMEOUT:?}",
            self.id
        );
    }

    /// Path of this node's control socket.
    pub fn ctl(&self) -> &Path {
        &self.ctl
    }

    /// Send one control request, panicking if the channel itself fails.
    pub fn call(&self, request: &Request) -> Response {
        Client::connect(&self.ctl)
            .expect("connect to the control channel")
            .call(request)
            .expect("control request")
    }

    /// The node's counters.
    pub fn counters(&self) -> up4_metrics::Snapshot {
        match self.call(&Request::Counters) {
            Response::Counters(s) => *s,
            other => panic!("counters replied {other:?}"),
        }
    }

    /// One node-wide counter by name.
    pub fn counter(&self, name: &str) -> u64 {
        *self
            .counters()
            .counters
            .get(name)
            .unwrap_or_else(|| panic!("no counter {name}"))
    }

    /// One per-vport counter by vport id and name.
    pub fn vport_counter(&self, vport: u16, name: &str) -> u64 {
        let snapshot = self.counters();
        let block = snapshot
            .vports
            .iter()
            .find(|v| v.id == vport)
            .unwrap_or_else(|| panic!("no vport {vport}"));
        *block
            .counters
            .get(name)
            .unwrap_or_else(|| panic!("no counter {name}"))
    }

    /// The process id, for signalling.
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Ask for a graceful shutdown and wait for the exit code.
    pub fn shutdown(mut self) -> std::process::ExitStatus {
        assert_eq!(self.call(&Request::Shutdown), Response::ShuttingDown);
        self.wait()
    }

    /// Send SIGTERM through `kill(1)` and wait for the exit code.
    ///
    /// The signal is sent by a child process rather than `libc::kill` because
    /// `unsafe` is confined to `up4-io` (spec S1.7, A7) — including in tests.
    pub fn terminate(mut self) -> std::process::ExitStatus {
        let status = Command::new("kill")
            .arg("-TERM")
            .arg(self.child.id().to_string())
            .status()
            .expect("run kill");
        assert!(status.success(), "kill -TERM failed");
        self.wait()
    }

    /// Kill the process outright, as a crash would.
    pub fn kill(mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.child = dummy_child();
    }

    fn wait(&mut self) -> std::process::ExitStatus {
        let deadline = Instant::now() + READY_TIMEOUT;
        loop {
            match self.child.try_wait().expect("wait for up4d") {
                Some(status) => {
                    self.child = dummy_child();
                    return status;
                }
                None if Instant::now() > deadline => panic!("up4d did not exit"),
                None => std::thread::sleep(Duration::from_millis(20)),
            }
        }
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A placeholder for a child that has already been reaped, so `Drop` has
/// something harmless to operate on.
fn dummy_child() -> Child {
    Command::new("true").spawn().expect("spawn /bin/true")
}

/// Wait until `check` holds, or fail after `within`.
pub fn wait_until(within: Duration, mut check: impl FnMut() -> bool) -> Duration {
    let start = Instant::now();
    while start.elapsed() < within {
        if check() {
            return start.elapsed();
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    panic!("condition did not hold within {within:?}");
}
