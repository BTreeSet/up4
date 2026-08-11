//! The `unsafe` allowlist (spec S1.7, A7), enforced in both directions.
//!
//! up4's central safety claim is that `unsafe` appears only where something
//! outside Rust's model genuinely requires it. A grep with a list of excluded
//! paths cannot support that claim: it says where nobody looked, not why the
//! code there is warranted, and it stays quiet when an exemption outlives its
//! reason.
//!
//! So the allowlist is a total map from *file* to [`Warrant`], and three
//! things are checked:
//!
//! 1. **Nothing unexplained.** Every file containing the keyword is listed.
//! 2. **Nothing silent.** The site count is exact, so `unsafe` cannot grow
//!    inside an already-allowed file without saying so.
//! 3. **Nothing stale.** Every entry still names a file that still uses it;
//!    an exemption that outlived its reason fails the build.
//!
//! The fourth check is what makes a warrant more than a label. [`Warrant`] is
//! a closed enum, so a new justification is a visible source change rather
//! than a new sentence in a comment — and each variant carries a structural
//! rule ([`Warrant::admits`]) that the file's own path must satisfy. Code
//! cannot be labelled `Generated` unless it really is under a generated
//! directory, or `SyscallPlumbing` unless it really is in the crate that owns
//! syscalls. The label and the fact are checked against each other.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Why a file is permitted to use `unsafe`.
///
/// Closed. Adding a category is a deliberate, reviewable act; it is not
/// possible to justify a new site by writing a new reason next to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Warrant {
    /// Calls into libc that have no safe equivalent. Confined to `up4-io` by
    /// spec S1.7: the crate that owns sockets, clocks, and signals.
    SyscallPlumbing,
    /// Compiler output. up4 does not edit it — editing it would break the
    /// regenerate-and-diff check — so the `unsafe` it contains is the
    /// upstream compiler's, reviewed once at the seam rather than per line.
    Generated,
    /// Benchmark scaffolding outside `crates/`, which is not part of the
    /// shipped switch. Today: the counting global allocator that proves the
    /// fast path allocates nothing (spec S13.5).
    BenchHarness,
}

impl Warrant {
    /// The structural rule a file must satisfy to carry this warrant.
    ///
    /// This is the half that makes the allowlist auditable rather than
    /// merely declarative: the reason has to be true of the path, so a
    /// hand-written file cannot be waved through as generated.
    fn admits(self, path: &str) -> bool {
        match self {
            Self::SyscallPlumbing => path.starts_with("crates/up4-io/"),
            Self::Generated => path.contains("/src/generated/"),
            Self::BenchHarness => !path.starts_with("crates/"),
        }
    }

    fn describe(self) -> &'static str {
        match self {
            Self::SyscallPlumbing => "syscall plumbing (must live under crates/up4-io/)",
            Self::Generated => "generated code (must live under a src/generated/ directory)",
            Self::BenchHarness => "bench scaffolding (must live outside crates/)",
        }
    }
}

/// One allowed file: where, how many sites, under which warrant, and why.
struct Exempt {
    path: &'static str,
    sites: usize,
    warrant: Warrant,
    why: &'static str,
}

/// The allowlist. Every `unsafe` in the repository is here or the build fails.
const ALLOWED: &[Exempt] = &[
    Exempt {
        path: "crates/up4-io/src/socket.rs",
        sites: 1,
        warrant: Warrant::SyscallPlumbing,
        why: "poll(2) for socket readiness; quinn-udp leaves the socket non-blocking (D7)",
    },
    Exempt {
        path: "crates/up4-io/src/clock.rs",
        sites: 1,
        warrant: Warrant::SyscallPlumbing,
        why: "clock_gettime(CLOCK_MONOTONIC) into a caller-owned timespec",
    },
    Exempt {
        path: "crates/up4-io/src/signal.rs",
        sites: 4,
        warrant: Warrant::SyscallPlumbing,
        why: "pthread_sigmask/sigwait: block terminating signals, then wait on one thread",
    },
    Exempt {
        path: "crates/up4-io/src/probe.rs",
        sites: 3,
        warrant: Warrant::SyscallPlumbing,
        why: "uname(2) and getsockopt(2) readback for the startup banner (spec S11.1)",
    },
    Exempt {
        path: "benches/src/lib.rs",
        sites: 9,
        warrant: Warrant::BenchHarness,
        why: "GlobalAlloc impl for the counting allocator that guards the zero-allocation fast path",
    },
    Exempt {
        path: "crates/up4-x4c/src/generated/l2fwd.rs",
        sites: 1,
        warrant: Warrant::Generated,
        why: "x4c emits `unsafe impl Send for main_pipeline`; up4 moves the instance to its shard thread",
    },
    Exempt {
        path: "crates/up4-x4c/src/generated/l3fwd.rs",
        sites: 1,
        warrant: Warrant::Generated,
        why: "x4c emits `unsafe impl Send for main_pipeline`; up4 moves the instance to its shard thread",
    },
];

/// This file talks *about* the keyword constantly and uses it never, so it is
/// the one path the scanner skips. Named explicitly rather than pattern-matched
/// so the exclusion cannot widen by accident.
const SELF_PATH: &str = "crates/up4d/tests/unsafe_audit.rs";

/// Directories scanned. `crates/` is the shipped switch; `benches/` is
/// scaffolding that is audited anyway so its exemption stays honest.
const ROOTS: [&str; 2] = ["crates", "benches"];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

/// Whether `line` uses the keyword, as opposed to mentioning it.
///
/// Excludes comments and the `forbid` attribute that proves its absence —
/// the same filter the workflow used, kept here so there is one definition.
fn uses_keyword(line: &str) -> bool {
    let t = line.trim_start();
    if t.starts_with("//") || t.starts_with('*') || t.starts_with("/*") {
        return false;
    }
    if line.contains("forbid(unsafe_code)") {
        return false;
    }
    let word = "unsafe";
    line.match_indices(word).any(|(i, _)| {
        let before = line[..i].chars().next_back();
        let after = line[i + word.len()..].chars().next();
        let boundary = |c: Option<char>| !c.is_some_and(|c| c.is_alphanumeric() || c == '_');
        boundary(before) && boundary(after)
    })
}

/// Every scanned file that uses the keyword, with its site count.
fn found() -> BTreeMap<String, usize> {
    fn walk(dir: &Path, root: &Path, out: &mut BTreeMap<String, usize>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().is_some_and(|n| n == "target") {
                    continue;
                }
                walk(&path, root, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let rel = path
                    .strip_prefix(root)
                    .expect("under root")
                    .to_string_lossy()
                    .into_owned();
                if rel == SELF_PATH {
                    continue;
                }
                let text = std::fs::read_to_string(&path).expect("read source");
                let n = text.lines().filter(|l| uses_keyword(l)).count();
                if n > 0 {
                    out.insert(rel, n);
                }
            }
        }
    }

    let root = repo_root();
    let mut out = BTreeMap::new();
    for r in ROOTS {
        walk(&root.join(r), &root, &mut out);
    }
    out
}

#[test]
fn every_use_of_unsafe_is_on_the_allowlist() {
    let allowed: BTreeMap<_, _> = ALLOWED.iter().map(|e| (e.path, e)).collect();
    for (path, sites) in found() {
        assert!(
            allowed.contains_key(path.as_str()),
            "{path} uses the unsafe keyword at {sites} site(s) and is not on the \
             allowlist (spec S1.7, A7). Add an entry to ALLOWED in {SELF_PATH} \
             with a Warrant and a reason, or remove the code."
        );
    }
}

#[test]
fn the_site_count_of_each_allowed_file_is_exact() {
    let found = found();
    for e in ALLOWED {
        let actual = found.get(e.path).copied().unwrap_or(0);
        assert_eq!(
            actual, e.sites,
            "{} is allowed {} site(s) but has {actual}. If the new site is \
             warranted, say so by updating `sites` — growth inside an allowed \
             file should be as visible as a new file.",
            e.path, e.sites
        );
    }
}

#[test]
fn no_exemption_outlives_its_reason() {
    let found = found();
    for e in ALLOWED {
        assert!(
            found.contains_key(e.path),
            "{} is on the allowlist but no longer uses the keyword (reason \
             given: {}). Remove the entry: an exemption nobody needs is an \
             exemption nobody is checking.",
            e.path,
            e.why
        );
    }
}

#[test]
fn every_warrant_is_true_of_the_path_it_justifies() {
    for e in ALLOWED {
        assert!(
            e.warrant.admits(e.path),
            "{} claims {:?}, but that warrant means: {}. The label and the \
             location disagree.",
            e.path,
            e.warrant,
            e.warrant.describe()
        );
    }
}

#[test]
fn the_allowlist_is_well_formed() {
    let mut paths: Vec<_> = ALLOWED.iter().map(|e| e.path).collect();
    let n = paths.len();
    paths.sort_unstable();
    paths.dedup();
    assert_eq!(
        paths.len(),
        n,
        "an allowlist with a duplicate path is ambiguous"
    );
    for e in ALLOWED {
        assert!(
            e.sites > 0,
            "{}: a zero-site exemption allows nothing",
            e.path
        );
        assert!(
            e.why.len() > 20,
            "{}: the reason must say what the code does, not that it is fine",
            e.path
        );
    }
}

#[test]
fn the_scanner_recognises_use_and_ignores_mention() {
    assert!(uses_keyword("unsafe impl Send for X {}"));
    assert!(uses_keyword("    let n = unsafe { libc::uname(&mut u) };"));
    assert!(uses_keyword("pub unsafe fn f() {}"));
    // Mentions, not uses.
    assert!(!uses_keyword("//! unsafe lives only in up4-io"));
    assert!(!uses_keyword("    // SAFETY: this unsafe block is fine"));
    assert!(!uses_keyword("     * unsafe in a block comment"));
    assert!(!uses_keyword("#![forbid(unsafe_code)]"));
    // Adjacent identifiers are not the keyword.
    assert!(!uses_keyword("#![deny(unsafe_op_in_unsafe_fn)]"));
    assert!(!uses_keyword("let unsafely = 1;"));
}

#[test]
fn the_scan_reaches_the_code_it_claims_to_audit() {
    // Guards against a vacuous pass: if the walk silently found nothing, every
    // assertion above would hold trivially.
    let found = found();
    assert!(
        found.contains_key("crates/up4-io/src/signal.rs"),
        "the scanner did not reach up4-io; it found: {:?}",
        found.keys().collect::<Vec<_>>()
    );
    assert!(
        found.len() >= 5,
        "suspiciously few files scanned: {found:?}"
    );
}
