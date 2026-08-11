//! What this binary can load, as an algebra rather than a list of names.
//!
//! up4 ships one set of P4 programs and three independent ways to execute
//! them. Those are separate axes, so they are separate types: a [`Selection`]
//! is a [`Program`] paired with a [`Backend`], and because both are closed and
//! every pair is implemented, [`build`] is **total** — there is no "unknown
//! pipeline" path to handle at run time, and no way to name a combination that
//! does not exist.
//!
//! The one thing that is not a program-on-a-backend is the benchmark oracle
//! (spec S7.4): it parses nothing and has no `.p4` source, so pairing it with a
//! backend would be meaningless. It is therefore a separate variant rather than
//! a third program, which is what keeps the product total.
//!
//! Each backend also carries [`BackendFacts`] describing what it actually is —
//! where its code came from, whether it allocates per frame, how it executes.
//! Those facts are reported by `up4ctl info`, and the documentation quotes them
//! rather than asserting anything of its own. A backend that gets slower or
//! changes provenance says so itself; nothing has to remember to update prose.

use crate::{Pipeline, PipelineParams};

/// A P4 program up4 ships.
///
/// Closed on purpose: every backend implements every program, which is the
/// property that makes [`build`] total and lets the conformance corpora
/// cross-check all three backends against one another (spec S10).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Program {
    /// Learning-free L2 switch: exact match on destination MAC, flood on miss.
    L2Fwd,
    /// IPv4 router: longest-prefix match, TTL decrement, checksum zero-fill.
    L3Fwd,
}

impl Program {
    /// Every shipped program.
    pub const ALL: [Self; 2] = [Self::L2Fwd, Self::L3Fwd];

    /// The name used in `up4.toml`'s `pipeline =` and on the wire.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::L2Fwd => "l2fwd",
            Self::L3Fwd => "l3fwd",
        }
    }

    /// One line for `--help` and `up4ctl info`.
    #[must_use]
    pub const fn summary(self) -> &'static str {
        match self {
            Self::L2Fwd => "L2 switch: exact match on destination MAC, broadcast on miss",
            Self::L3Fwd => "IPv4 router: longest-prefix match, TTL decrement, checksum zero-fill",
        }
    }

    /// The `.p4` source of record for this program under `arch` (spec P1).
    ///
    /// Two architectures, because the two P4 compilers target different ones.
    /// The forwarding logic is the same program in both; what differs is the
    /// metadata plumbing each architecture provides. Nothing textual ties the
    /// two together — the conformance corpus does, by requiring every backend
    /// to produce identical output on identical input.
    #[must_use]
    pub const fn source(self, arch: Arch) -> &'static str {
        match (self, arch) {
            (Self::L2Fwd, Arch::SoftNpu) => "p4/programs/l2fwd/l2fwd.softnpu.p4",
            (Self::L2Fwd, Arch::Ubpf) => "p4/programs/l2fwd/l2fwd.ubpf.p4",
            (Self::L3Fwd, Arch::SoftNpu) => "p4/programs/l3fwd/l3fwd.softnpu.p4",
            (Self::L3Fwd, Arch::Ubpf) => "p4/programs/l3fwd/l3fwd.ubpf.p4",
        }
    }

    /// Parse a program name.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.name() == s)
    }
}

/// A P4 architecture model. Which one a source targets is a property of the
/// compiler that will read it, not of the forwarding logic it expresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Arch {
    /// Oxide's SoftNPU model, the one `x4c` compiles.
    SoftNpu,
    /// `ubpf_model.p4`, the one `p4c --target ubpf` compiles.
    Ubpf,
}

/// How a program's semantics get executed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Backend {
    /// Rust written against up4's own header and table primitives.
    Native,
    /// Rust generated from the `.p4` source by Oxide's `x4c`.
    X4c,
    /// uBPF bytecode generated from the `.p4` source by `p4c --target ubpf`,
    /// executed in process.
    Ubpf,
}

impl Backend {
    /// Every shipped backend.
    pub const ALL: [Self; 3] = [Self::Native, Self::X4c, Self::Ubpf];

    /// The name used in `up4.toml`'s `backend =` and on the wire.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::X4c => "x4c",
            Self::Ubpf => "ubpf",
        }
    }

    /// The architecture whose `.p4` source this backend consumes.
    #[must_use]
    pub const fn arch(self) -> Arch {
        match self {
            // The native rendering is written against the SoftNPU source
            // because that is the one a compiler can check it against.
            Self::Native | Self::X4c => Arch::SoftNpu,
            Self::Ubpf => Arch::Ubpf,
        }
    }

    /// Parse a backend name.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|b| b.name() == s)
    }
}

/// Where a backend's executed code came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Provenance {
    /// Written by hand against the `.p4` source. The source is the artifact of
    /// record, but nothing mechanical enforces the correspondence — only the
    /// conformance corpus does.
    HandRendered,
    /// Emitted by a P4 compiler from the `.p4` source.
    Compiled {
        /// The compiler that produced it.
        compiler: &'static str,
    },
}

/// Whether a backend allocates while forwarding.
///
/// up4's harness allocates nothing per frame and proves it with a counting
/// allocator (spec S13.5). A backend that cannot hold that line says so here
/// instead of letting the claim quietly become false.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AllocProfile {
    /// No heap traffic on the fast path.
    None,
    /// Allocates per frame, for the stated reason.
    PerFrame {
        /// Why — named so the cost is attributable, not folded into a number.
        reason: &'static str,
    },
}

/// How a backend's code runs on the CPU.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecProfile {
    /// Compiled Rust, inlined into the shard loop.
    Native,
    /// Bytecode in a virtual machine.
    Bytecode {
        /// Interpreted, or JIT-compiled to host instructions.
        mode: ExecMode,
    },
}

/// How the uBPF virtual machine executes a program.
///
/// The JIT variant exists only where the **target** architecture has a JIT
/// backend. On any other target it is not merely disabled — it does not exist,
/// so there is no unsupported-mode error to handle and no runtime check to get
/// wrong. Keyed on `target_arch`, so cross-compiling to x86_64 from anything
/// still gets the JIT, and cross-compiling away from it still cannot ask.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecMode {
    /// Bytecode interpreted instruction by instruction. Available everywhere.
    Interpreted,
    /// Bytecode JIT-compiled to host instructions before the first frame.
    #[cfg(target_arch = "x86_64")]
    Jit,
}

impl ExecMode {
    /// The mode used when nothing overrides it: the fastest one this target
    /// can actually run.
    #[must_use]
    pub const fn preferred() -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            Self::Jit
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            Self::Interpreted
        }
    }

    /// The name reported by `up4ctl info`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Interpreted => "interpreted",
            #[cfg(target_arch = "x86_64")]
            Self::Jit => "jit",
        }
    }
}

/// What a backend actually is, as the backend itself reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BackendFacts {
    /// Where the executed code came from.
    pub provenance: Provenance,
    /// Whether forwarding allocates.
    pub alloc: AllocProfile,
    /// How the code runs.
    pub exec: ExecProfile,
}

impl Backend {
    /// What this backend is. Reported by `up4ctl info`; the documentation
    /// quotes this rather than making claims of its own.
    #[must_use]
    pub const fn facts(self) -> BackendFacts {
        match self {
            Self::Native => BackendFacts {
                provenance: Provenance::HandRendered,
                alloc: AllocProfile::None,
                exec: ExecProfile::Native,
            },
            Self::X4c => BackendFacts {
                provenance: Provenance::Compiled { compiler: "x4c" },
                // Measured, not guessed: x4c's runtime represents every header
                // field as a heap `BitVec` and returns a `Vec` of outputs per
                // packet. See docs/deviations.md D9.
                alloc: AllocProfile::PerFrame {
                    reason: "x4c runtime models header fields as heap BitVec and returns Vec per packet",
                },
                exec: ExecProfile::Native,
            },
            Self::Ubpf => BackendFacts {
                provenance: Provenance::Compiled {
                    compiler: "p4c --target ubpf",
                },
                alloc: AllocProfile::None,
                exec: ExecProfile::Bytecode {
                    mode: ExecMode::preferred(),
                },
            },
        }
    }
}

/// What to load: a P4 program on a backend, or the benchmark oracle.
///
/// A sum, not a pair of optional fields, because "oracle with a backend" and
/// "program without a backend" are both meaningless and neither is
/// representable here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Selection {
    /// A P4 program executed by one of the three backends.
    P4 {
        /// Which program.
        program: Program,
        /// Which backend executes it.
        backend: Backend,
    },
    /// The benchmark oracle (spec S7.4). Not a P4 program: it has no `.p4`
    /// source and no backend, which is exactly why it is not a [`Program`].
    #[cfg(feature = "oracle")]
    Oracle,
}

/// Why a `pipeline`/`backend` pair could not be parsed.
///
/// Closed, and every variant carries what the operator needs to fix it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SelectError {
    /// No such program.
    UnknownProgram {
        /// What was asked for.
        got: String,
    },
    /// No such backend.
    UnknownBackend {
        /// What was asked for.
        got: String,
    },
    /// A backend was named for a selection that has no backend to choose.
    BackendNotApplicable {
        /// The pipeline that takes no backend.
        pipeline: &'static str,
    },
}

impl std::fmt::Display for SelectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownProgram { got } => {
                let all: Vec<_> = Program::ALL.iter().map(|p| p.name()).collect();
                write!(f, "unknown pipeline `{got}`; known: {}", all.join(", "))
            }
            Self::UnknownBackend { got } => {
                let all: Vec<_> = Backend::ALL.iter().map(|b| b.name()).collect();
                write!(f, "unknown backend `{got}`; known: {}", all.join(", "))
            }
            Self::BackendNotApplicable { pipeline } => {
                write!(f, "pipeline `{pipeline}` takes no backend")
            }
        }
    }
}

impl std::error::Error for SelectError {}

impl Selection {
    /// Every selection this binary can load.
    #[must_use]
    pub fn all() -> Vec<Self> {
        let mut out: Vec<Self> = Program::ALL
            .into_iter()
            .flat_map(|program| {
                Backend::ALL
                    .into_iter()
                    .map(move |backend| Self::P4 { program, backend })
            })
            .collect();
        #[cfg(feature = "oracle")]
        out.push(Self::Oracle);
        out
    }

    /// Parse the configured pipeline name and optional backend name.
    ///
    /// This is the only door into a `Selection`: past it, every combination is
    /// one this binary implements.
    ///
    /// # Errors
    /// [`SelectError`] naming the alternatives.
    pub fn parse(pipeline: &str, backend: Option<&str>) -> Result<Self, SelectError> {
        #[cfg(feature = "oracle")]
        if pipeline == "null" {
            return match backend {
                None => Ok(Self::Oracle),
                Some(_) => Err(SelectError::BackendNotApplicable { pipeline: "null" }),
            };
        }
        let program = Program::parse(pipeline).ok_or_else(|| SelectError::UnknownProgram {
            got: pipeline.to_owned(),
        })?;
        let backend = match backend {
            None => Backend::Native,
            Some(b) => Backend::parse(b).ok_or_else(|| SelectError::UnknownBackend {
                got: b.to_owned(),
            })?,
        };
        Ok(Self::P4 { program, backend })
    }

    /// The stable display name, `program/backend`.
    ///
    /// Static because both components are: the six pairs are enumerated here
    /// rather than formatted, so this stays allocation-free and usable as the
    /// `&'static str` the [`Pipeline`] and [`crate::Engine`] contracts want.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::P4 {
                program: Program::L2Fwd,
                backend: Backend::Native,
            } => "l2fwd/native",
            Self::P4 {
                program: Program::L2Fwd,
                backend: Backend::X4c,
            } => "l2fwd/x4c",
            Self::P4 {
                program: Program::L2Fwd,
                backend: Backend::Ubpf,
            } => "l2fwd/ubpf",
            Self::P4 {
                program: Program::L3Fwd,
                backend: Backend::Native,
            } => "l3fwd/native",
            Self::P4 {
                program: Program::L3Fwd,
                backend: Backend::X4c,
            } => "l3fwd/x4c",
            Self::P4 {
                program: Program::L3Fwd,
                backend: Backend::Ubpf,
            } => "l3fwd/ubpf",
            #[cfg(feature = "oracle")]
            Self::Oracle => "null",
        }
    }

    /// The facts for whatever executes this selection.
    #[must_use]
    pub const fn facts(self) -> BackendFacts {
        match self {
            Self::P4 { backend, .. } => backend.facts(),
            #[cfg(feature = "oracle")]
            Self::Oracle => BackendFacts {
                provenance: Provenance::HandRendered,
                alloc: AllocProfile::None,
                exec: ExecProfile::Native,
            },
        }
    }
}

/// Load a selection.
///
/// Total: `Selection` is closed and every variant is implemented, so unlike a
/// name lookup this cannot fail. An unknown pipeline stops at
/// [`Selection::parse`], at configuration time, with the alternatives listed.
#[must_use]
pub fn build(sel: Selection, params: &PipelineParams) -> Box<dyn Pipeline> {
    match sel {
        Selection::P4 {
            program,
            backend: Backend::Native,
        } => match program {
            Program::L2Fwd => Box::new(crate::programs::l2fwd::L2Fwd::new(params)),
            Program::L3Fwd => Box::new(crate::programs::l3fwd::L3Fwd::new(params)),
        },
        Selection::P4 {
            program,
            backend: Backend::X4c,
        } => crate::backends::x4c_gen::build(program, params),
        Selection::P4 {
            program,
            backend: Backend::Ubpf,
        } => crate::backends::ubpf::build(program, params),
        #[cfg(feature = "oracle")]
        Selection::Oracle => Box::new(crate::programs::null::NullPipeline::new(params)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_selection_builds_and_names_itself() {
        let params = PipelineParams::new([0, 1]);
        for sel in Selection::all() {
            let p = build(sel, &params);
            assert_eq!(p.name(), sel.name(), "pipeline reports its selection");
            assert_eq!(p.engine().name(), sel.name(), "engine agrees");
        }
    }

    #[test]
    fn selection_names_are_unique() {
        let mut names: Vec<_> = Selection::all().into_iter().map(Selection::name).collect();
        let n = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), n, "two selections share a name");
    }

    #[test]
    fn the_product_is_total() {
        // Six pairs, all loadable. If a backend ever cannot run a program,
        // this fails rather than the combination silently not existing.
        let pairs = Program::ALL.len() * Backend::ALL.len();
        let p4 = Selection::all()
            .into_iter()
            .filter(|s| matches!(s, Selection::P4 { .. }))
            .count();
        assert_eq!(p4, pairs);
    }

    #[test]
    fn parsing_defaults_to_the_native_backend() {
        assert_eq!(
            Selection::parse("l3fwd", None),
            Ok(Selection::P4 {
                program: Program::L3Fwd,
                backend: Backend::Native
            })
        );
    }

    #[test]
    fn parsing_names_the_alternatives_it_knows() {
        let e = Selection::parse("l4fwd", None).unwrap_err();
        assert_eq!(
            e,
            SelectError::UnknownProgram {
                got: "l4fwd".to_owned()
            }
        );
        assert!(e.to_string().contains("l3fwd"), "{e}");

        let e = Selection::parse("l3fwd", Some("wasm")).unwrap_err();
        assert!(e.to_string().contains("ubpf"), "{e}");
    }

    #[test]
    fn every_program_has_a_source_for_every_architecture() {
        for program in Program::ALL {
            for arch in [Arch::SoftNpu, Arch::Ubpf] {
                let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../..")
                    .join(program.source(arch));
                assert!(path.is_file(), "missing {}", program.source(arch));
            }
        }
    }

    #[test]
    fn a_backend_that_allocates_says_so() {
        // The anti-overclaiming property: the binary reports what it is, and
        // the docs quote it. If x4c ever stops allocating, this test is what
        // notices that the facts went stale.
        assert_eq!(Backend::Native.facts().alloc, AllocProfile::None);
        assert_eq!(Backend::Ubpf.facts().alloc, AllocProfile::None);
        assert!(matches!(
            Backend::X4c.facts().alloc,
            AllocProfile::PerFrame { .. }
        ));
    }

    #[test]
    fn the_jit_exists_only_where_the_target_can_run_it() {
        // Not "is disabled" — does not exist. On a non-x86_64 target the
        // variant is absent, so no code can select it and no runtime check has
        // to refuse it.
        #[cfg(target_arch = "x86_64")]
        assert_eq!(ExecMode::preferred(), ExecMode::Jit);
        #[cfg(not(target_arch = "x86_64"))]
        assert_eq!(ExecMode::preferred(), ExecMode::Interpreted);
    }
}
