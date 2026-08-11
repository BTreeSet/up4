//! The CI cache-key invariant, enforced rather than remembered.
//!
//! A GitHub Actions cache entry holds one job's `./target` directory. Naming
//! that entry after the job says nothing about what is inside it, so two jobs
//! building different cargo profiles could hand each other artifacts built
//! with different flags — a cache that restores successfully and is wrong.
//!
//! The invariant that removes the possibility:
//!
//! > **A `shared-key` is exactly the name of the cargo profile whose artifacts
//! > the entry holds, and a job builds exactly that one profile.**
//!
//! Both halves are checked here. The first makes the key meaningful; without
//! the second the key could be accurate today and quietly wrong after someone
//! adds a `--release` step to a `dev`-keyed job — which is precisely the drift
//! that prompted this file.
//!
//! New profiles are a supported way to grow: declare `[profile.<name>]` in the
//! workspace manifest and the key `<name>` becomes legal here automatically.
//! Nothing in this test enumerates profiles by hand.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

/// Cargo's built-in profiles, which need no declaration to be real.
const BUILT_IN: [&str; 4] = ["dev", "release", "test", "bench"];

/// `test` artifacts are built with the `dev` profile's settings and `bench`
/// with `release`'s, so each pair shares one set of artifacts and therefore one
/// cache entry. The root is the name that entry is called.
fn family_root(profile: &str) -> &str {
    match profile {
        "test" => "dev",
        "bench" => "release",
        other => other,
    }
}

/// Every profile name that may legally appear as a cache key.
fn declared_profiles() -> BTreeSet<String> {
    let manifest =
        std::fs::read_to_string(repo_root().join("Cargo.toml")).expect("workspace manifest");
    let custom = manifest.lines().filter_map(|l| {
        l.trim()
            .strip_prefix("[profile.")?
            .strip_suffix(']')
            .map(str::to_owned)
    });
    BUILT_IN
        .into_iter()
        .map(str::to_owned)
        .chain(custom)
        .collect()
}

/// What one CI job declares: its cache key, and the profiles its steps build.
#[derive(Default, Debug)]
struct Job {
    shared_key: Option<String>,
    builds: BTreeSet<String>,
}

/// Which profile a `cargo` invocation produces artifacts under, or `None` when
/// it compiles nothing (`cargo fmt`, `cargo --version`).
///
/// `--profile <name>` yields that name verbatim, including custom profiles: a
/// custom profile gets its own `target/<name>/` directory whatever it inherits
/// from, so it is its own cache entry and must be able to say so.
fn profile_of(cmd: &str) -> Option<String> {
    let mut words = cmd.split_whitespace().skip_while(|w| *w != "cargo").skip(1);
    // Skip toolchain selectors like `cargo +nightly build`.
    let sub = words.find(|w| !w.starts_with('+'))?;
    let compiles = matches!(sub, "build" | "test" | "clippy" | "run" | "check" | "bench");
    if !compiles {
        return None;
    }
    if let Some(rest) = cmd.split("--profile").nth(1) {
        return Some(rest.split_whitespace().next()?.to_owned());
    }
    if cmd.contains("--release") {
        return Some("release".to_owned());
    }
    Some(if sub == "bench" { "bench" } else { "dev" }.to_owned())
}

/// Parse the workflow into jobs. The format is fixed and shallow — jobs at two
/// spaces, everything else deeper — so a scanner is honest here and avoids a
/// YAML dependency the workspace does not otherwise need (spec S2).
fn jobs() -> BTreeMap<String, Job> {
    // Every workflow, not just ci.yml: an invariant that one file can evade by
    // adding another is not an invariant.
    let dir = repo_root().join(".github/workflows");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .expect("workflows directory")
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "yml" || e == "yaml"))
        .collect();
    files.sort();
    assert!(
        !files.is_empty(),
        "no workflows found under {}",
        dir.display()
    );
    files.into_iter().flat_map(|f| jobs_in(&f)).collect()
}

/// Parse one workflow. Job keys are `file:job`, so two workflows may each have
/// a job called `verify` without colliding.
fn jobs_in(path: &Path) -> BTreeMap<String, Job> {
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let yaml = std::fs::read_to_string(path).expect("workflow");
    let mut jobs = BTreeMap::new();
    let mut current: Option<String> = None;
    let mut in_jobs = false;

    for line in yaml.lines() {
        if line.starts_with("jobs:") {
            in_jobs = true;
            continue;
        }
        if !in_jobs {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // A job header: exactly two spaces of indent, ending in a colon.
        if indent == 2
            && let Some(name) = trimmed.strip_suffix(':')
            && !name.contains(' ')
        {
            let key = format!("{stem}:{name}");
            current = Some(key.clone());
            jobs.entry(key).or_insert_with(Job::default);
            continue;
        }
        let Some(job) = current.as_ref().and_then(|c| jobs.get_mut(c)) else {
            continue;
        };
        if let Some(key) = trimmed.strip_prefix("shared-key:") {
            job.shared_key = Some(key.trim().to_owned());
        }
        if trimmed.contains("cargo ")
            && let Some(p) = profile_of(trimmed)
        {
            job.builds.insert(family_root(&p).to_owned());
        }
    }
    jobs
}

#[test]
fn every_cache_key_is_a_declared_cargo_profile() {
    let profiles = declared_profiles();
    let mut keyed = 0;
    for (name, job) in jobs() {
        let Some(key) = &job.shared_key else { continue };
        keyed += 1;
        assert!(
            profiles.contains(key),
            "job `{name}` caches under `{key}`, which is not a cargo profile. \
             Declare [profile.{key}] in the workspace manifest, or use one of: {}",
            profiles.iter().cloned().collect::<Vec<_>>().join(", ")
        );
        assert_eq!(
            family_root(key),
            key,
            "job `{name}` caches under `{key}`, but `{key}` artifacts are built \
             with `{}`'s settings and belong in that entry",
            family_root(key)
        );
    }
    assert!(keyed > 0, "no cache keys found — did the workflow move?");
}

#[test]
fn a_keyed_job_builds_exactly_the_profile_its_key_names() {
    for (name, job) in jobs() {
        let Some(key) = &job.shared_key else { continue };
        let want: BTreeSet<String> = std::iter::once(key.clone()).collect();
        assert_eq!(
            job.builds, want,
            "job `{name}` caches under `{key}` but builds {:?}. An entry holds \
             one profile's artifacts; a job that builds two profiles cannot \
             honestly name either one.",
            job.builds
        );
    }
}

#[test]
fn a_job_that_builds_nothing_claims_no_cache_entry() {
    for (name, job) in jobs() {
        if job.builds.is_empty() {
            assert!(
                job.shared_key.is_none(),
                "job `{name}` builds no up4 artifacts but claims cache entry \
                 `{}`. An entry named after a profile must hold that profile's \
                 output; an empty target directory is not that.",
                job.shared_key.as_deref().unwrap_or_default()
            );
        }
    }
}

#[test]
fn the_scanner_reads_the_workflow_it_thinks_it_reads() {
    // Guards the parser itself: if the workflow is restructured such that jobs
    // stop being found, the assertions above would pass vacuously.
    let jobs = jobs();
    for expected in ["ci:check", "ci:smoke", "ci:p4", "p4-artifacts:verify"] {
        assert!(jobs.contains_key(expected), "job `{expected}` not parsed");
    }
    assert_eq!(
        jobs["ci:check"].shared_key.as_deref(),
        Some("dev"),
        "the test job caches dev artifacts"
    );
    assert_eq!(
        jobs["ci:smoke"].shared_key.as_deref(),
        Some("release"),
        "the smoke job caches release artifacts"
    );
}

#[test]
fn profile_detection_maps_commands_to_the_entry_they_belong_in() {
    let cases = [
        ("cargo fmt --all --check", None),
        ("cargo test --workspace", Some("dev")),
        (
            "cargo clippy --workspace --all-targets -- -D warnings",
            Some("dev"),
        ),
        (
            "cargo run -p up4-tools --bin probe -- --peer 127.0.0.1",
            Some("dev"),
        ),
        ("cargo build --release --workspace", Some("release")),
        ("cargo bench -p benches", Some("bench")),
        ("rustup show active-toolchain", None),
        // A custom profile keeps its own name: it gets its own target
        // directory, so it is its own entry. This is what makes declaring a
        // new profile — say one for a target that has a uBPF JIT and one for a
        // target that does not — a supported move rather than a special case.
        ("cargo build --profile jit --workspace", Some("jit")),
        ("cargo test --profile nojit", Some("nojit")),
    ];
    for (cmd, want) in cases {
        assert_eq!(profile_of(cmd).as_deref(), want, "{cmd}");
    }
    // A custom profile is its own family root; only cargo's two built-in
    // aliases collapse.
    assert_eq!(family_root("jit"), "jit");
    // …and the families they collapse into.
    assert_eq!(family_root("bench"), "release");
    assert_eq!(family_root("test"), "dev");
}
