//! Provisioning the compilers, in userspace, with everything pinned.
//!
//! Nothing here needs root, a system package manager, or a container. The
//! chain bottoms out at two things a developer already has to build up4 at
//! all — `cargo` and `git` — plus one static binary fetched over HTTPS.
//!
//! Every version is pinned, and that is load-bearing rather than tidy: `verify`
//! compares committed artifacts byte for byte, so an unpinned compiler would
//! make a clean checkout look stale on a machine whose `clang` differs from
//! the one that last generated. Pinning is what makes the comparison mean
//! "the source changed" instead of "the toolchain moved".

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

/// x4c and its `p4rs` runtime are one artifact; this revision must match the
/// `p4rs` pin in `crates/up4-x4c/Cargo.toml`, or generated code and the
/// runtime it calls into can disagree.
const X4C_REPO: &str = "https://github.com/oxidecomputer/p4";
const X4C_REV: &str = "e29b7953ed6c0577d7e170a8d83d20b0f989d240";

const P4C_REPO: &str = "https://github.com/p4lang/p4c";
const P4C_REV: &str = "8ce422be06326cc9e902ae70ca5b9916515443c6";

/// micromamba is a single static binary, which is the whole reason it is here:
/// it bootstraps a C/C++ toolchain and p4c's build dependencies into a prefix
/// without touching the system.
const MICROMAMBA_URL: &str = "https://micro.mamba.pm/api/micromamba/linux-aarch64/latest";
const MICROMAMBA_URL_X86: &str = "https://micro.mamba.pm/api/micromamba/linux-64/latest";

/// p4c's build dependencies, and clang.
///
/// `protobuf`, `grpc`, and `bdw-gc` are deliberately absent: p4c vendors its
/// own abseil and bdw-gc through CMake's FetchContent, and supplying conda's
/// as well makes the headers (a different abseil LTS) disagree with the
/// archives actually linked. That failure is a wall of undefined references
/// with no obvious cause, so it is worth naming here.
const CONDA_SPECS: &[&str] = &[
    "cmake",
    "ninja",
    "make",
    "pkg-config",
    "bison",
    "flex",
    "libboost-devel",
    "gmp",
    "clangdev=19",
    "python=3.11",
];

/// A compiler this repository needs but does not vendor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tool {
    /// Oxide's P4-to-Rust compiler.
    X4c,
    /// `p4c` built with only its uBPF backend.
    P4cUbpf,
    /// The C-to-BPF compiler, from the pinned environment rather than the host.
    Clang,
    /// From the repository's pinned Rust toolchain; already on PATH.
    Rustfmt,
}

impl Tool {
    fn name(self) -> &'static str {
        match self {
            Self::X4c => "x4c",
            Self::P4cUbpf => "p4c-ubpf",
            Self::Clang => "clang",
            Self::Rustfmt => "rustfmt",
        }
    }
}

/// Resolved paths to every provisioned tool.
pub struct Toolchain {
    paths: BTreeMap<Tool, PathBuf>,
    conda_prefix: PathBuf,
    p4c_src: PathBuf,
}

impl Toolchain {
    /// The binary for `tool`. Panics if it was not requested at provision
    /// time — a programming error, since the set comes from the targets.
    pub fn path(&self, tool: Tool) -> &Path {
        self.paths
            .get(&tool)
            .unwrap_or_else(|| panic!("{} was not provisioned", tool.name()))
    }

    /// Environment p4c needs to find the conda runtime it linked against.
    pub fn env(&self) -> Vec<(String, String)> {
        let lib = self.conda_prefix.join("lib");
        let existing = std::env::var("LD_LIBRARY_PATH").unwrap_or_default();
        vec![(
            "LD_LIBRARY_PATH".into(),
            format!("{}:{existing}", lib.display()),
        )]
    }

    /// p4c's uBPF runtime header, which its generated C includes.
    pub fn ubpf_runtime_header(&self) -> PathBuf {
        self.p4c_src.join("backends/ubpf/runtime/ubpf_common.h")
    }

    /// Ensure every tool in `needed` is present under `cache`, building what
    /// is missing. Idempotent: a warm cache does nothing.
    pub fn provision(needed: &[Tool], cache: &Path) -> Result<Self, String> {
        std::fs::create_dir_all(cache).map_err(|e| e.to_string())?;
        let mut paths = BTreeMap::new();
        let conda_prefix = cache.join("conda/envs/p4c");
        let p4c_src = cache.join("p4c-src");

        let wants_conda = needed.contains(&Tool::P4cUbpf) || needed.contains(&Tool::Clang);
        if wants_conda {
            ensure_conda_env(cache, &conda_prefix)?;
        }

        for &tool in needed {
            let path = match tool {
                Tool::Rustfmt => which("rustfmt")?,
                Tool::Clang => {
                    let p = conda_prefix.join("bin/clang");
                    require(&p, "clang from the pinned conda environment")?
                }
                Tool::X4c => ensure_x4c(cache)?,
                Tool::P4cUbpf => ensure_p4c(&conda_prefix, &p4c_src)?,
            };
            paths.insert(tool, path);
        }
        Ok(Self {
            paths,
            conda_prefix,
            p4c_src,
        })
    }
}

fn require(p: &Path, what: &str) -> Result<PathBuf, String> {
    if p.is_file() {
        Ok(p.to_path_buf())
    } else {
        Err(format!("{what} missing at {}", p.display()))
    }
}

fn which(bin: &str) -> Result<PathBuf, String> {
    let out = Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {bin}"))
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(format!("{bin} not on PATH"));
    }
    Ok(PathBuf::from(
        String::from_utf8_lossy(&out.stdout).trim().to_string(),
    ))
}

fn sh(what: &str, script: &str, cwd: Option<&Path>) -> Result<(), String> {
    eprintln!("==> {what}");
    let mut cmd = Command::new("bash");
    cmd.arg("-euo").arg("pipefail").arg("-c").arg(script);
    if let Some(d) = cwd {
        cmd.current_dir(d);
    }
    let status = cmd.status().map_err(|e| format!("{what}: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{what}: exited {status}"))
    }
}

fn ensure_micromamba(cache: &Path) -> Result<PathBuf, String> {
    let mm = cache.join("micromamba/bin/micromamba");
    if mm.is_file() {
        return Ok(mm);
    }
    let url = if cfg!(target_arch = "x86_64") {
        MICROMAMBA_URL_X86
    } else {
        MICROMAMBA_URL
    };
    let dir = cache.join("micromamba");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    sh(
        "fetching micromamba",
        &format!("curl -sSL '{url}' | tar -xj bin/micromamba"),
        Some(&dir),
    )?;
    require(&mm, "micromamba")
}

fn ensure_conda_env(cache: &Path, prefix: &Path) -> Result<(), String> {
    if prefix.join("bin/clang").is_file() && prefix.join("bin/bison").is_file() {
        return Ok(());
    }
    let mm = ensure_micromamba(cache)?;
    let root = cache.join("conda");
    sh(
        "creating the p4c build environment (userspace, no root)",
        &format!(
            "MAMBA_ROOT_PREFIX='{}' '{}' create -y -p '{}' -c conda-forge {}",
            root.display(),
            mm.display(),
            prefix.display(),
            CONDA_SPECS.join(" ")
        ),
        None,
    )
}

fn ensure_x4c(cache: &Path) -> Result<PathBuf, String> {
    let src = cache.join("x4c-src");
    let bin = src.join("target/release/x4c");
    if bin.is_file() {
        return Ok(bin);
    }
    sh(
        "building x4c",
        &format!(
            "rm -rf '{d}' && git init -q '{d}' && cd '{d}' && \
             git remote add origin {repo} && \
             git fetch -q --depth 1 origin {rev} && git checkout -q FETCH_HEAD && \
             rm -f rust-toolchain.toml && cargo build --release -p x4c",
            d = src.display(),
            repo = X4C_REPO,
            rev = X4C_REV,
        ),
        None,
    )?;
    require(&bin, "x4c")
}

fn ensure_p4c(prefix: &Path, src: &Path) -> Result<PathBuf, String> {
    let bin = src.join("build/backends/ubpf/p4c-ubpf");
    if bin.is_file() {
        return Ok(bin);
    }
    sh(
        "building p4c's uBPF backend (this takes a while, once)",
        &format!(
            "rm -rf '{d}' && git init -q '{d}' && cd '{d}' && \
             git remote add origin {repo} && \
             git fetch -q --depth 1 origin {rev} && git checkout -q FETCH_HEAD && \
             git submodule update -q --init --depth 1 --recursive && \
             export PATH='{p}/bin':$PATH CMAKE_PREFIX_PATH='{p}' \
                    LD_LIBRARY_PATH='{p}/lib' CONDA_PREFIX='{p}' && \
             export CC=$(ls '{p}'/bin/*-linux-gnu-gcc 2>/dev/null | head -1) \
                    CXX=$(ls '{p}'/bin/*-linux-gnu-g++ 2>/dev/null | head -1) && \
             cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
               -DENABLE_UBPF=ON -DENABLE_BMV2=OFF -DENABLE_EBPF=OFF \
               -DENABLE_DPDK=OFF -DENABLE_TC=OFF -DENABLE_P4TEST=OFF \
               -DENABLE_P4C_GRAPHS=OFF -DENABLE_P4FMT=OFF -DENABLE_TEST_TOOLS=OFF \
               -DENABLE_GTESTS=OFF -DENABLE_DOCS=OFF -DENABLE_P4TOOLS=OFF \
               -DENABLE_BMV2_PSA=OFF -DENABLE_MULTITHREAD=OFF && \
             cmake --build build --target p4c-ubpf -j$(nproc)",
            d = src.display(),
            repo = P4C_REPO,
            rev = P4C_REV,
            p = prefix.display(),
        ),
        None,
    )?;
    require(&bin, "p4c-ubpf")
}
