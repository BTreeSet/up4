//! Loading a pipeline: the one place every backend is named.
#![deny(missing_docs)]
//!
//! [`up4_engine::catalog`] models what can be loaded (`Program × Backend` as
//! closed sums), but it cannot *build* the compiled backends without depending
//! on them, and they depend on it. So the total function lives here, in the
//! crate above all three, where the dependency graph is a DAG.
//!
//! [`build`] is total. `Selection` is closed and every variant is implemented,
//! so unlike a name lookup this cannot fail: an unknown pipeline stops at
//! `Selection::parse`, at configuration time, with the alternatives listed.

use up4_engine::catalog::{Backend, Program, Selection};
use up4_engine::{Pipeline, PipelineParams};

/// Load a selection. Total over `Selection`.
///
/// What a backend runs is `admit(program) ; p4(program) ; scrub(program)`:
/// the program's ingress check and its departing fix-up wrapped around the
/// compiled P4 (see [`up4_engine::envelope`]). The `native` rendering already
/// fuses both ends into its own parser and deparser, so wrapping it would be a
/// second pass over the same bytes for the same answer; the compiled backends
/// are opaque and compose them explicitly. All three end up computing the same
/// function, which is what the conformance corpus checks with no exceptions to
/// its name.
#[must_use]
pub fn build(sel: Selection, params: &PipelineParams) -> Box<dyn Pipeline> {
    match sel {
        Selection::P4 {
            program,
            backend: Backend::Native,
        } => match program {
            Program::L2Fwd => Box::new(up4_engine::programs::l2fwd::L2Fwd::new(params)),
            Program::L3Fwd => Box::new(up4_engine::programs::l3fwd::L3Fwd::new(params)),
        },
        Selection::P4 {
            program,
            backend: Backend::X4c,
        } => program.envelope().wrap(match program {
            Program::L2Fwd => Box::new(up4_x4c::pipeline::X4cPipeline::l2fwd(params)),
            Program::L3Fwd => Box::new(up4_x4c::pipeline::X4cPipeline::l3fwd(params)),
        }),
        Selection::P4 {
            program,
            backend: Backend::Ubpf,
        } => program.envelope().wrap(match program {
            Program::L2Fwd => Box::new(up4_ubpf::pipeline::UbpfPipeline::l2fwd(params)),
            Program::L3Fwd => Box::new(up4_ubpf::pipeline::UbpfPipeline::l3fwd(params)),
        }),
        Selection::Oracle => Box::new(up4_engine::programs::null::NullPipeline::new(params)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The property the whole three-backend design exists to have: every
    /// program runs on every backend, and each reports the selection it is.
    #[test]
    fn every_selection_builds_and_names_itself() {
        let params = PipelineParams::new([0, 1]);
        for sel in Selection::all() {
            let p = build(sel, &params);
            assert_eq!(p.name(), sel.name(), "pipeline reports its selection");
            assert_eq!(p.engine().name(), sel.name(), "engine agrees");
        }
    }

    /// Interchangeability is a claim about the *control plane* too: the same
    /// `up4ctl` call must be accepted by every backend of a program, because
    /// all three are the same tables of the same `.p4`.
    #[test]
    fn every_backend_of_a_program_exposes_the_same_tables() {
        let params = PipelineParams::new([0, 1]);
        for program in Program::ALL {
            let shapes: Vec<Vec<&str>> = Backend::ALL
                .into_iter()
                .map(|backend| {
                    let p = build(Selection::P4 { program, backend }, &params);
                    p.tables().schemas().iter().map(|s| s.name).collect()
                })
                .collect();
            assert!(
                shapes.windows(2).all(|w| w[0] == w[1]),
                "{}: backends disagree about their tables: {shapes:?}",
                program.name()
            );
        }
    }
}
