//! The null oracle (spec S7.4) — **benchmarks only**.
//!
//! Feature-gated behind `oracle` and excluded from default builds, because it
//! is the one component allowed to decide an output port without a P4 program
//! (spec S1.3's single exception). Its purpose is to measure the harness: with
//! parsing and table lookup removed, `benches/io_only` sees the cost of the
//! I/O path alone.
//!
//! The map is static, built once from the topology: egress is the next vport in
//! configuration order, cyclically — which for the two-port topology the
//! acceptance criteria use is exactly `Forward(1 - ingress)`.
//!
//! Cost: one array read per frame.

use crate::{
    Engine, FrameCtx, Pipeline, PipelineParams, Verdict,
    shim::{NoTables, TableOps},
};
use std::sync::Arc;

/// Registered name.
pub const NAME: &str = "null";

/// The loaded oracle.
#[derive(Debug)]
pub struct NullPipeline {
    /// Indexed by ingress vport id; `None` for ids the topology does not have.
    egress: Arc<[Option<u16>]>,
    tables: NoTables,
}

impl NullPipeline {
    /// Build the static map from the node's vports.
    #[must_use]
    pub fn new(params: &PipelineParams) -> Self {
        let width = params
            .vports
            .iter()
            .copied()
            .max()
            .map_or(0, |m| usize::from(m) + 1);
        let mut egress = vec![None; width];
        for (i, id) in params.vports.iter().enumerate() {
            let next = params.vports[(i + 1) % params.vports.len()];
            egress[usize::from(*id)] = Some(next);
        }
        Self {
            egress: egress.into(),
            tables: NoTables(NAME),
        }
    }
}

impl Pipeline for NullPipeline {
    fn name(&self) -> &'static str {
        NAME
    }

    fn engine(&self) -> Box<dyn Engine> {
        Box::new(NullEngine {
            egress: Arc::clone(&self.egress),
        })
    }

    fn tables(&self) -> &dyn TableOps {
        &self.tables
    }
}

/// One shard's view of the oracle.
#[derive(Debug)]
struct NullEngine {
    egress: Arc<[Option<u16>]>,
}

impl Engine for NullEngine {
    #[inline]
    fn process(&mut self, f: &mut FrameCtx<'_>) -> Verdict {
        match self
            .egress
            .get(usize::from(f.ingress_vport))
            .copied()
            .flatten()
        {
            Some(port) => Verdict::Forward(port),
            None => Verdict::Drop,
        }
    }

    fn name(&self) -> &'static str {
        NAME
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verdict(p: &NullPipeline, ingress: u16) -> Verdict {
        let mut e = p.engine();
        let mut buf = [0u8; 128];
        let mut ctx = FrameCtx::new(&mut buf, 64, 60, ingress, 0).expect("fits");
        e.process(&mut ctx)
    }

    #[test]
    fn two_ports_echo_to_the_other_one() {
        let p = NullPipeline::new(&PipelineParams::new([0, 1]));
        assert_eq!(verdict(&p, 0), Verdict::Forward(1));
        assert_eq!(verdict(&p, 1), Verdict::Forward(0));
    }

    #[test]
    fn other_topologies_get_the_cyclic_successor() {
        let p = NullPipeline::new(&PipelineParams::new([3, 7, 9]));
        assert_eq!(verdict(&p, 3), Verdict::Forward(7));
        assert_eq!(verdict(&p, 7), Verdict::Forward(9));
        assert_eq!(verdict(&p, 9), Verdict::Forward(3));
        assert_eq!(verdict(&p, 4), Verdict::Drop, "an id the topology lacks");
    }

    #[test]
    fn it_parses_nothing_and_has_no_tables() {
        let p = NullPipeline::new(&PipelineParams::new([0, 1]));
        let mut e = p.engine();
        let mut buf = [0u8; 64];
        let mut ctx = FrameCtx::new(&mut buf, 64, 0, 0, 0).expect("fits");
        assert_eq!(
            e.process(&mut ctx),
            Verdict::Forward(1),
            "an empty frame is still forwarded"
        );
        assert!(p.tables().table_dump("x").is_err());
    }
}
