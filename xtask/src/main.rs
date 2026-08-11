//! up4's generation toolchain, as a model rather than a script.
//!
//! Two of up4's three backends are compiler output. Their artifacts are
//! committed, so the repository can be built without either compiler present —
//! and so those artifacts can be reviewed. That arrangement has one failure
//! mode: a `.p4` source edited without regenerating, leaving committed code
//! that no longer corresponds to its source of record.
//!
//! This binary exists to make that state detectable and fixable. The shape:
//!
//! * A [`Target`] is a committed artifact that a compiler produced. It knows
//!   its source, its outputs, and its [`Recipe`] — a list of [`Step`]s that are
//!   *data*, not actions.
//! * [`realize`] runs a recipe into a scratch directory and returns
//!   `(produced, committed)` pairs. It is the only code that runs a compiler.
//! * A [`Mode`] is an interpretation of those pairs: [`Realized::Check`] discards
//!   them, [`Realized::Generate`] copies produced over committed, [`Realized::Verify`]
//!   compares bytes and reports divergence.
//!
//! So "regenerate" and "is the checkout stale?" are not two procedures that
//! must be kept in step — they are one procedure consumed two ways, and they
//! cannot disagree.
//!
//! **Userspace, no root.** Every tool is provisioned into a cache directory
//! without a package manager that needs privileges: micromamba is a static
//! binary, p4c is built from source inside a micromamba environment, and clang
//! comes from that same environment rather than the host. That last point is
//! not convenience — BPF object files are compared byte for byte, so the
//! compiler that produces them has to be pinned, not whatever the runner
//! happens to ship.

use std::path::{Path, PathBuf};
use std::process::Command;

use up4_engine::catalog::{Arch, Program};

mod tool;
use tool::{Tool, Toolchain};

/// What the caller wants done with the artifacts a recipe produces.
///
/// Closed, and every variant is a fold over the same `(produced, committed)`
/// pairs — which is what keeps regeneration and staleness-detection from
/// drifting apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// Compare each `.p4` against the hash recorded when its artifact was
    /// generated. Needs **no compiler**, so it runs in a second on any
    /// machine — which is what makes it the gate every pull request can
    /// afford. It catches the failure that actually happens: a source edited
    /// without regenerating.
    Audit,
    /// A mode that has to run the compilers first.
    Realized(Realized),
}

/// The modes that consume `(produced, committed)` pairs, and so must build.
///
/// Split from [`Mode`] so that the loop over produced artifacts is total over
/// *this* type: `Audit` returns before a compiler is provisioned, and rather
/// than leave an unreachable arm to assert about, it is simply not in the sum
/// the loop eliminates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Realized {
    /// Run the compilers, keep nothing. Answers "does the source compile?".
    Check,
    /// Copy what the compilers produced over what is committed.
    Generate,
    /// Regenerate and compare bytes. Needs the toolchain.
    Verify,
}

impl Mode {
    /// Whether this mode has to provision the P4 compilers. Building them
    /// takes tens of minutes, so a mode that can avoid it must.
    fn parse(s: &str) -> Option<Self> {
        match s {
            "audit" => Some(Self::Audit),
            "check" => Some(Self::Realized(Realized::Check)),
            "generate" => Some(Self::Realized(Realized::Generate)),
            "verify" => Some(Self::Realized(Realized::Verify)),
            _ => None,
        }
    }
}

/// A committed artifact that a compiler produced.
///
/// Closed over the backends that need generation. `native` is absent because
/// it is written by hand — there is nothing to regenerate, which is exactly
/// the property that distinguishes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Target {
    /// `*.softnpu.p4` → x4c → a Rust module in `up4-x4c`.
    X4cRust(Program),
    /// `*.ubpf.p4` → p4c-ubpf → C → clang → a BPF object in `up4-ubpf`.
    UbpfObject(Program),
}

impl Target {
    fn all() -> Vec<Self> {
        Program::ALL
            .into_iter()
            .flat_map(|p| [Self::X4cRust(p), Self::UbpfObject(p)])
            .collect()
    }

    fn program(self) -> Program {
        match self {
            Self::X4cRust(p) | Self::UbpfObject(p) => p,
        }
    }

    fn label(self) -> String {
        match self {
            Self::X4cRust(p) => format!("{}/x4c", p.name()),
            Self::UbpfObject(p) => format!("{}/ubpf", p.name()),
        }
    }

    /// The `.p4` source of record this target is derived from.
    fn source(self) -> &'static str {
        match self {
            Self::X4cRust(p) => p.source(Arch::SoftNpu),
            Self::UbpfObject(p) => p.source(Arch::Ubpf),
        }
    }

    /// Where the artifacts live in the tree, relative to the repo root.
    ///
    /// The uBPF target commits both the C and the object: the C is what a
    /// human reviews, the object is what `include_bytes!` embeds. Committing
    /// only the object would mean reviewing a binary; only the C would mean
    /// needing clang to build up4.
    fn committed(self) -> Vec<String> {
        let n = self.program().name();
        match self {
            Self::X4cRust(_) => vec![format!("crates/up4-x4c/src/generated/{n}.rs")],
            Self::UbpfObject(_) => vec![
                format!("crates/up4-ubpf/src/generated/{n}.h"),
                format!("crates/up4-ubpf/src/generated/{n}.c"),
                format!("crates/up4-ubpf/src/generated/{n}.o"),
            ],
        }
    }

    /// How strongly a committed artifact can be checked against its source.
    ///
    /// Not every compiler is reproducible, and saying so in the type is better
    /// than a byte comparison that fails for the wrong reason.
    fn fidelity(self) -> Fidelity {
        match self {
            // x4c emits items in a nondeterministic order — two runs over an
            // unchanged source produce files of identical length with blocks
            // in different positions, which is what an unordered map in a code
            // generator looks like from outside. Byte comparison would report
            // staleness on every run, so the witness is the source hash.
            Self::X4cRust(_) => Fidelity::SourceWitness,
            // p4c stamps a timestamp and an absolute path into its header
            // comment; with that one line normalised, its C and the object
            // clang builds from it are byte-reproducible.
            Self::UbpfObject(_) => Fidelity::ByteIdentical,
        }
    }

    /// Which tools this target needs provisioned.
    fn tools(self) -> Vec<Tool> {
        match self {
            Self::X4cRust(_) => vec![Tool::X4c, Tool::Rustfmt],
            Self::UbpfObject(_) => vec![Tool::P4cUbpf, Tool::Clang],
        }
    }
}

/// Run a target's recipe into `stage`, returning `(produced, committed)` pairs.
///
/// The only function that runs a compiler. Every mode goes through it, so a
/// mode cannot accidentally produce artifacts a different way.
fn realize(
    target: Target,
    tc: &Toolchain,
    root: &Path,
    stage: &Path,
) -> Result<Vec<(PathBuf, PathBuf)>, String> {
    let name = target.program().name();
    let src = root.join(target.source());
    std::fs::create_dir_all(stage).map_err(|e| e.to_string())?;

    match target {
        Target::X4cRust(_) => {
            // x4c resolves `#include <...>` relative to the source file's own
            // directory and offers no include path, so the program is staged
            // beside the vendored architecture model.
            for m in ["core.p4", "softnpu.p4"] {
                copy(&root.join("p4/include/softnpu").join(m), &stage.join(m))?;
            }
            let staged_src = stage.join(format!("{name}.softnpu.p4"));
            copy(&src, &staged_src)?;

            let out = stage.join(format!("{name}.rs"));
            run(Command::new(tc.path(Tool::X4c))
                .current_dir(stage)
                .arg(staged_src.file_name().unwrap())
                .arg("-o")
                .arg(out.file_name().unwrap()))?;

            // x4c emits `_main_pipeline_create` so SoftNPU can dlopen a
            // pipeline as a shared object. It is `#[no_mangle]`, so two
            // programs in one crate collide on the symbol; up4 links
            // statically and calls `main_pipeline::new()`, so it is
            // unreachable here as well as unbuildable.
            strip_dylib_shim(&out)?;

            // Format on generation. `cargo fmt --check` covers the workspace,
            // and formatting afterwards would make the committed file differ
            // from what the generator emits — which is what Verify detects.
            run(Command::new(tc.path(Tool::Rustfmt))
                .arg("--edition")
                .arg("2024")
                .arg(&out))?;

            Ok(vec![(out, root.join(&target.committed()[0]))])
        }

        Target::UbpfObject(_) => {
            let c = stage.join(format!("{name}.c"));
            run(Command::new(tc.path(Tool::P4cUbpf))
                .arg("-I")
                .arg(root.join("p4/include/ubpf"))
                .arg("--target")
                .arg("ubpf")
                .arg("-o")
                .arg(&c)
                .arg(&src)
                .envs(tc.env()))?;

            // p4c stamps the absolute source path and the wall-clock time
            // into the first line. Neither is part of the program, and both
            // would make the file differ on every run and every machine.
            normalise_p4c_header(&c)?;

            // p4c emits `#include "ubpf_common.h"`, which is part of its
            // runtime rather than of the program.
            copy(&tc.ubpf_runtime_header(), &stage.join("ubpf_common.h"))?;

            let obj = stage.join(format!("{name}.o"));
            run(Command::new(tc.path(Tool::Clang))
                .current_dir(stage)
                // `-nostdlibinc` keeps clang to its own resource headers.
                // BPF is a freestanding target with no libc, and the generated
                // C needs only stdint/stdbool/stddef, which clang ships. It
                // also removes the host's glibc headers from the inputs, so
                // the object bytes do not depend on the machine that built it
                // — which is what makes byte-comparison in Verify meaningful.
                .args(["-O2", "-target", "bpf", "-nostdlibinc", "-c"])
                .arg(c.file_name().unwrap())
                .arg("-o")
                .arg(obj.file_name().unwrap()))?;

            let committed = target.committed();
            Ok(vec![
                // The header carries the key and value struct layouts the host
                // has to reproduce byte for byte, so it is part of the
                // artifact, not a build leftover: without it the committed C
                // does not even compile.
                (stage.join(format!("{name}.h")), root.join(&committed[0])),
                (c, root.join(&committed[1])),
                (obj, root.join(&committed[2])),
            ])
        }
    }
}

/// Replace p4c's timestamped, absolute-path banner with a stable one.
fn normalise_p4c_header(path: &Path) -> Result<(), String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let mut lines: Vec<&str> = text.lines().collect();
    let stable = "/* Automatically generated by p4c-ubpf. Do not edit; see p4/generated.lock.";
    if lines.first().is_some_and(|l| l.contains("p4c-ubpf")) {
        lines[0] = stable;
    }
    std::fs::write(path, lines.join("\n") + "\n").map_err(|e| e.to_string())
}

fn strip_dylib_shim(path: &Path) -> Result<(), String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let mut out = String::with_capacity(text.len());
    let mut skipping = false;
    for line in text.lines() {
        if line.trim_start().starts_with("#[unsafe(no_mangle)]") {
            skipping = true;
            continue;
        }
        if skipping {
            if line == "}" {
                skipping = false;
            }
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    std::fs::write(path, out).map_err(|e| e.to_string())
}

fn copy(from: &Path, to: &Path) -> Result<(), String> {
    if let Some(d) = to.parent() {
        std::fs::create_dir_all(d).map_err(|e| format!("{}: {e}", d.display()))?;
    }
    std::fs::copy(from, to)
        .map(|_| ())
        .map_err(|e| format!("copy {} -> {}: {e}", from.display(), to.display()))
}

fn run(cmd: &mut Command) -> Result<(), String> {
    let out = cmd
        .output()
        .map_err(|e| format!("spawn {:?}: {e}", cmd.get_program()))?;
    if out.status.success() {
        return Ok(());
    }
    Err(format!(
        "{:?} failed ({})\n{}{}",
        cmd.get_program(),
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    ))
}

/// How a committed artifact is checked against its `.p4` source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fidelity {
    /// Regenerate and compare bytes. Catches a stale artifact *and* a
    /// hand-edited one.
    ByteIdentical,
    /// Compare a hash of the source against the one recorded when the artifact
    /// was generated. Catches the failure that actually happens — a `.p4`
    /// edited without regenerating — but not a hand-edited artifact, because
    /// the compiler does not produce a stable target to compare against.
    SourceWitness,
}

/// A non-cryptographic hash: this distinguishes "the source changed" from
/// "it did not", which is an accident-detection problem, not an adversarial
/// one. Named FNV-1a rather than left as a magic loop so the choice is legible.
fn fnv1a(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |h, &b| {
        (h ^ u64::from(b)).wrapping_mul(0x1000_0000_01b3)
    })
}

/// The witness file: which source, at which content hash, produced which
/// artifacts, using which pinned tool.
const WITNESS: &str = "p4/generated.lock";

fn witness_line(target: Target, root: &Path) -> Result<String, String> {
    let src = root.join(target.source());
    let bytes = std::fs::read(&src).map_err(|e| format!("{}: {e}", src.display()))?;
    Ok(format!(
        "{}  {}  {:016x}",
        target.label(),
        target.source(),
        fnv1a(&bytes)
    ))
}

/// The report a run produces: one line per artifact, plus what diverged.
#[derive(Default)]
struct Report {
    checked: usize,
    written: Vec<String>,
    diverged: Vec<String>,
}

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(mode) = args.first().and_then(|s| Mode::parse(s)) else {
        eprintln!(
            "usage: cargo xtask <check|generate|verify> [program]\n\
             \n\
               audit     no compilers: are the .p4 sources the ones the\n\
                         committed artifacts were generated from?\n\
               check     compile every source, keep nothing\n\
               generate  regenerate committed artifacts from the .p4 sources\n\
               verify    fail if any committed artifact differs from its source\n"
        );
        return std::process::ExitCode::from(2);
    };
    let only = args.get(1).and_then(|s| Program::parse(s));

    let root = repo_root();
    let cache = std::env::var("UP4_TOOLCHAIN_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| root.join(".toolchain"));

    let targets: Vec<_> = Target::all()
        .into_iter()
        .filter(|t| only.is_none_or(|p| t.program() == p))
        .collect();

    // Provision only what the selected targets actually need: checking one
    // program should not build the other compiler.
    let mut needed: Vec<Tool> = targets.iter().flat_map(|t| t.tools()).collect();
    needed.sort_unstable();
    needed.dedup();

    let Mode::Realized(mode) = mode else {
        return audit(&targets, &root);
    };

    let tc = match Toolchain::provision(&needed, &cache) {
        Ok(tc) => tc,
        Err(e) => {
            eprintln!("toolchain: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };

    let stage_root = cache.join("stage");
    let _ = std::fs::remove_dir_all(&stage_root);
    let mut report = Report::default();
    let mut witnesses: Vec<String> = Vec::new();

    for target in targets {
        let stage = stage_root.join(target.label().replace('/', "-"));
        let pairs = match realize(target, &tc, &root, &stage) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{}: {e}", target.label());
                return std::process::ExitCode::FAILURE;
            }
        };
        report.checked += 1;

        let line = match witness_line(target, &root) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("{e}");
                return std::process::ExitCode::FAILURE;
            }
        };
        witnesses.push(line.clone());

        for (produced, committed) in pairs {
            let rel = committed
                .strip_prefix(&root)
                .unwrap_or(&committed)
                .display()
                .to_string();
            match mode {
                Realized::Check => {}
                Realized::Generate => {
                    if let Err(e) = copy(&produced, &committed) {
                        eprintln!("{e}");
                        return std::process::ExitCode::FAILURE;
                    }
                    report.written.push(rel);
                }
                // Only where the compiler is reproducible; elsewhere the
                // source witness below is the check.
                Realized::Verify if target.fidelity() == Fidelity::ByteIdentical => {
                    let want = std::fs::read(&produced).unwrap_or_default();
                    let have = std::fs::read(&committed).unwrap_or_default();
                    if want != have {
                        report.diverged.push(format!(
                            "{rel} ({} vs {} bytes)",
                            have.len(),
                            want.len()
                        ));
                    }
                }
                Realized::Verify => {}
            }
        }
        println!("{:<14} {}", target.label(), target.source());
    }

    match mode {
        Realized::Check => println!("\n{} source(s) compile", report.checked),
        Realized::Generate => {
            let body = format!(
                "# Written by `cargo xtask generate`. Each line records the .p4\n\
                 # source an artifact was produced from, and a hash of that\n\
                 # source at the time. `cargo xtask verify` recomputes it.\n{}\n",
                witnesses.join("\n")
            );
            if let Err(e) = std::fs::write(root.join(WITNESS), body) {
                eprintln!("{WITNESS}: {e}");
                return std::process::ExitCode::FAILURE;
            }
            for w in &report.written {
                println!("wrote {w}");
            }
            println!("wrote {WITNESS}");
        }
        Realized::Verify => {
            // The witness catches the failure that actually happens: a `.p4`
            // edited without regenerating. It covers every target, including
            // the ones whose compiler is not byte-reproducible.
            let recorded = std::fs::read_to_string(root.join(WITNESS)).unwrap_or_default();
            for w in &witnesses {
                if !recorded.lines().any(|l| l.trim() == w) {
                    let label = w.split_whitespace().next().unwrap_or("?");
                    report
                        .diverged
                        .push(format!("{label}: source changed since it was generated"));
                }
            }
            return finish(&report);
        }
    }
    std::process::ExitCode::SUCCESS
}

/// The compiler-free gate: every target's source must hash to what was
/// recorded when its artifact was generated.
///
/// Cost: one read and one pass per `.p4`. Nothing is built, nothing is
/// fetched, so this is affordable on every pull request — unlike the byte
/// comparison, which has to build two P4 compilers first.
fn audit(targets: &[Target], root: &Path) -> std::process::ExitCode {
    let recorded = match std::fs::read_to_string(root.join(WITNESS)) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("{WITNESS}: {e}\nRun `cargo xtask generate` to create it.");
            return std::process::ExitCode::FAILURE;
        }
    };
    let mut report = Report::default();
    for &target in targets {
        match witness_line(target, root) {
            Ok(w) => {
                if recorded.lines().any(|l| l.trim() == w) {
                    println!("{:<14} {}", target.label(), target.source());
                } else {
                    report
                        .diverged
                        .push(format!("{}: {}", target.label(), target.source()));
                }
            }
            Err(e) => {
                eprintln!("{e}");
                return std::process::ExitCode::FAILURE;
            }
        }
    }
    finish(&report)
}

/// Report a Verify outcome. Split out so both the byte and witness checks
/// end the same way.
fn finish(report: &Report) -> std::process::ExitCode {
    if report.diverged.is_empty() {
        println!("\nevery committed artifact matches its .p4 source");
        return std::process::ExitCode::SUCCESS;
    }
    eprintln!("\n{} artifact(s) are stale:", report.diverged.len());
    for d in &report.diverged {
        eprintln!("  {d}");
    }
    eprintln!(
        "\nA `.p4` source changed without its artifact being regenerated.\n\
         Reconcile with:\n\n    cargo xtask generate\n\n\
         and commit the result. CI cannot do this for you: the workflow token\n\
         is read-only by design (contents: read, no persisted credentials), so\n\
         a job that rewrote the tree would be a hole in the trust boundary\n\
         rather than a convenience."
    );
    std::process::ExitCode::FAILURE
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .canonicalize()
        .expect("repo root")
}
