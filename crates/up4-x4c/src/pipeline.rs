//! Adapting x4c's generated pipelines onto up4's `Engine`/`Pipeline`.
//!
//! # The mismatch
//!
//! up4 publishes table state with copy-on-write RCU: one writer swaps an
//! `Arc`, and every shard reads lock-free. x4c's `main_pipeline` takes
//! `&mut self` for *both* `process_packet` and `add_table_entry`, so it cannot
//! sit behind a shared snapshot at all — there is no immutable view of it to
//! publish.
//!
//! # The reconciliation
//!
//! Publish the *history* instead of the state. The shared value is an
//! append-only [`Journal`] of control-plane operations; each shard owns a
//! private `main_pipeline` and folds the journal into it:
//!
//! ```text
//! state(shard) = fold(apply, main_pipeline::new(radix), journal.ops)
//! ```
//!
//! `apply` is deterministic and the log is the same for every shard, so all
//! shards converge on identical table state without any of them sharing a
//! mutable pipeline. Publication stays copy-on-write; only what is published
//! changed.
//!
//! # Cost
//!
//! Steady state is one `Acquire` load and an integer compare per frame — the
//! same as [`up4_engine::table::Cached`], which this deliberately mirrors. The
//! first frame after a control-plane write replays the *k* new operations,
//! O(k). A compaction rewrites the log to one operation per live entry and
//! bumps the generation, which costs the next frame on each shard a rebuild of
//! O(n) for n live entries; at spec A2's 1000 routes that is milliseconds,
//! well inside A4's 100 ms visibility budget. Compaction is amortised O(1) per
//! operation, so a long-running switch with route churn keeps a bounded log.
//!
//! Per frame this backend copies the frame in and the result out, on top of
//! the allocations x4c's runtime performs internally. That is this backend's
//! declared profile (`Backend::facts()`), not an oversight: `packet_out`
//! borrows the input buffer, so the result cannot be written back over the
//! bytes it still points at.

use std::sync::Arc;

use up4_engine::table::Shared;
use up4_engine::{
    ActionSchema, Engine, EntryDesc, FrameCtx, Pipeline, PipelineParams, TableError, TableOps,
    TableSchema, TypedKey, TypedVal, Verdict,
};

use crate::abi::{encode_key, encode_params};
use crate::generated::{l2fwd, l3fwd};

/// up4's reserved egress ports (spec S5), as the P4 sources write them.
const PUNT_PORT: u16 = 65535;
const BROADCAST_PORT: u16 = 65534;

/// Everything program-specific, as data.
///
/// One value per shipped program, so adding a program is a new `Desc` rather
/// than a new branch in each of the functions below.
struct Desc {
    /// The selection name this pipeline reports.
    name: &'static str,
    /// The control-plane surface — reused verbatim from the `native` backend,
    /// because both are the same tables of the same `.p4`. That reuse is what
    /// makes the two backends interchangeable rather than merely parallel.
    schemas: &'static [TableSchema],
    /// Schema table name → the identifier x4c gives it. x4c qualifies a table
    /// with the control it is declared in; up4's schemas do not.
    ids: &'static [(&'static str, &'static str)],
    /// Construct a fresh pipeline with `radix` ports.
    new: fn(u16) -> Box<dyn p4rs::Pipeline>,
    /// Bytes the program's parser extracts before it can accept.
    ///
    /// P4 says a parser that runs out of bytes rejects the packet. p4rs does
    /// not implement that: `packet_in::extract` slices unconditionally and
    /// **panics** on a short frame (`lang/p4rs/src/lib.rs`). up4 runs with
    /// `panic = "abort"`, so the panic cannot be caught — a 13-byte frame
    /// would take the switch down. Refusing the frame here restores the
    /// semantics the source of record already specifies.
    min_parse: usize,
}

const L2FWD: Desc = Desc {
    name: "l2fwd/x4c",
    schemas: up4_engine::programs::l2fwd::SCHEMAS,
    ids: &[("mac_dst", "ingress.mac_dst")],
    new: |radix| Box::new(l2fwd::main_pipeline::new(radix)),
    // ethernet_h
    min_parse: 14,
};

const L3FWD: Desc = Desc {
    name: "l3fwd/x4c",
    schemas: up4_engine::programs::l3fwd::SCHEMAS,
    ids: &[("ipv4_lpm", "ingress.ipv4_lpm")],
    new: |radix| Box::new(l3fwd::main_pipeline::new(radix)),
    // ethernet_h + ipv4_h, both extracted unconditionally
    min_parse: 34,
};

impl Desc {
    fn schema(&self, table: &str) -> Result<&'static TableSchema, TableError> {
        self.schemas
            .iter()
            .find(|s| s.name == table)
            .ok_or_else(|| TableError::UnknownTable {
                name: table.to_owned(),
                known: self.schemas.iter().map(|s| s.name.to_owned()).collect(),
            })
    }

    /// The x4c identifier for a schema table. Total over `schemas`, which
    /// `every_schema_has_an_x4c_identifier` checks.
    fn id(&self, table: &str) -> &'static str {
        self.ids
            .iter()
            .find(|(n, _)| *n == table)
            .map(|(_, id)| *id)
            .unwrap_or_else(|| panic!("no x4c identifier for table `{table}`"))
    }
}

/// One control-plane operation, kept so it can be replayed.
///
/// Typed rather than pre-encoded: the byte encoding is derived on replay, so
/// `abi` stays the single definition of it.
#[derive(Clone, Debug)]
enum Op {
    Add {
        table: &'static str,
        key: TypedKey,
        action: &'static str,
        params: Vec<TypedVal>,
    },
    Remove {
        table: &'static str,
        key: TypedKey,
    },
}

/// One installed entry, kept for dumps and for compaction.
#[derive(Clone, Debug)]
struct Live {
    key: TypedKey,
    action: &'static str,
    params: Vec<TypedVal>,
}

/// The published value: a replayable history plus the live set it implies.
///
/// `generation` distinguishes "more operations were appended" (replay the
/// tail) from "the log was rewritten" (rebuild), which is what lets the log be
/// compacted without invalidating a shard's position in it.
#[derive(Clone, Debug, Default)]
struct Journal {
    generation: u64,
    ops: Vec<Op>,
    live: Vec<((&'static str, String), Live)>,
}

impl Journal {
    fn find(&self, table: &str, key: &TypedKey) -> Option<usize> {
        let k = key_id(key);
        self.live
            .iter()
            .position(|((t, kk), _)| *t == table && *kk == k)
    }

    /// Rewrite the log as one `Add` per live entry when it has grown past
    /// twice the live set. Amortised O(1) per operation.
    fn compact(&mut self) {
        if self.ops.len() <= 2 * self.live.len() + 16 {
            return;
        }
        self.ops = self
            .live
            .iter()
            .map(|((table, _), e)| Op::Add {
                table,
                key: e.key,
                action: e.action,
                params: e.params.clone(),
            })
            .collect();
        self.generation += 1;
    }
}

/// A stable identity for a key, for the live set.
fn key_id(key: &TypedKey) -> String {
    match key {
        TypedKey::Exact(v) => format!("{v}"),
        TypedKey::Lpm { value, prefix_len } => format!("{value}/{prefix_len}"),
    }
}

/// A loaded x4c pipeline: the shared journal and the topology it was built for.
pub struct X4cPipeline {
    desc: &'static Desc,
    radix: u16,
    journal: Arc<Shared<Journal>>,
}

impl X4cPipeline {
    fn new(desc: &'static Desc, params: &PipelineParams) -> Self {
        // The radix is deliberately larger than the topology.
        //
        // SoftNPU expresses broadcast as `egress.broadcast = true`, and x4c
        // expands that into one output per port other than the ingress one.
        // With a radix that exactly covers the vports, a two-port node's
        // broadcast produces a single output — indistinguishable from a
        // forward, which would silently mis-attribute every flooded frame to
        // `tx_pkts` instead of `tx_broadcast`.
        //
        // Two spare ports make the two cases structurally distinct: a forward
        // is always exactly one output, a broadcast always at least two. up4's
        // harness resolves `Verdict::Broadcast` against the real topology
        // itself, so the spare ports are never transmitted on — they exist
        // only so the verdict can be read off unambiguously.
        let highest = params.vports.iter().copied().max().unwrap_or(0);
        Self {
            desc,
            radix: highest.saturating_add(3),
            journal: Arc::new(Shared::new(Journal::default())),
        }
    }

    /// The `l2fwd` program on this backend.
    #[must_use]
    pub fn l2fwd(params: &PipelineParams) -> Self {
        Self::new(&L2FWD, params)
    }

    /// The `l3fwd` program on this backend.
    #[must_use]
    pub fn l3fwd(params: &PipelineParams) -> Self {
        Self::new(&L3FWD, params)
    }
}

impl Pipeline for X4cPipeline {
    fn name(&self) -> &'static str {
        self.desc.name
    }

    fn engine(&self) -> Box<dyn Engine> {
        Box::new(X4cEngine {
            desc: self.desc,
            journal: Arc::clone(&self.journal),
            pipe: (self.desc.new)(self.radix),
            radix: self.radix,
            generation: 0,
            applied: 0,
            version: u64::MAX, // forces a first sync
            scratch_in: Vec::with_capacity(2048),
            scratch_out: Vec::with_capacity(2048),
        })
    }

    fn tables(&self) -> &dyn TableOps {
        self
    }
}

impl TableOps for X4cPipeline {
    fn schemas(&self) -> &'static [TableSchema] {
        self.desc.schemas
    }

    fn table_add(
        &self,
        table: &str,
        key: TypedKey,
        action: &str,
        params: &[TypedVal],
    ) -> Result<(), TableError> {
        let schema = self.desc.schema(table)?;
        schema.check_key(&key)?;
        let action: &'static ActionSchema = schema.check(action, params)?;

        self.journal.update(|j| {
            let mut next = j.clone();
            let entry = Live {
                key,
                action: action.name,
                params: params.to_vec(),
            };
            let id = (schema.name, key_id(&key));
            match next.find(schema.name, &key) {
                Some(i) => next.live[i].1 = entry,
                None => next.live.push((id, entry)),
            }
            next.ops.push(Op::Add {
                table: schema.name,
                key,
                action: action.name,
                params: params.to_vec(),
            });
            next.compact();
            (next, ())
        });
        Ok(())
    }

    fn table_remove(&self, table: &str, key: TypedKey) -> Result<(), TableError> {
        let schema = self.desc.schema(table)?;
        schema.check_key(&key)?;
        self.journal.update(|j| {
            let mut next = j.clone();
            if let Some(i) = next.find(schema.name, &key) {
                next.live.remove(i);
            }
            next.ops.push(Op::Remove {
                table: schema.name,
                key,
            });
            next.compact();
            (next, ())
        });
        Ok(())
    }

    fn table_clear(&self, table: &str) -> Result<usize, TableError> {
        let schema = self.desc.schema(table)?;
        Ok(self.journal.update(|j| {
            let mut next = j.clone();
            let victims: Vec<TypedKey> = next
                .live
                .iter()
                .filter(|((t, _), _)| *t == schema.name)
                .map(|(_, e)| e.key)
                .collect();
            next.live.retain(|((t, _), _)| *t != schema.name);
            let n = victims.len();
            next.ops.extend(victims.into_iter().map(|key| Op::Remove {
                table: schema.name,
                key,
            }));
            next.compact();
            (next, n)
        }))
    }

    fn table_dump(&self, table: &str) -> Result<Vec<EntryDesc>, TableError> {
        let schema = self.desc.schema(table)?;
        let j = self.journal.load();
        let mut out: Vec<EntryDesc> = j
            .live
            .iter()
            .filter(|((t, _), _)| *t == schema.name)
            .map(|(_, e)| describe(schema, e))
            .collect();
        out.sort_by(|a, b| a.key.cmp(&b.key));
        Ok(out)
    }

    fn table_default(&self, table: &str) -> Result<EntryDesc, TableError> {
        let schema = self.desc.schema(table)?;
        // The miss action is compiled into the generated code by the P4
        // `default_action` declaration; x4c exposes no way to read it back, so
        // it is reported from the source of record instead.
        Ok(EntryDesc {
            key: "*".to_owned(),
            action: default_action_of(schema).to_owned(),
            params: std::collections::BTreeMap::new(),
        })
    }

    fn table_set_default(
        &self,
        table: &str,
        _action: &str,
        _params: &[TypedVal],
    ) -> Result<(), TableError> {
        let schema = self.desc.schema(table)?;
        Err(TableError::Unsupported {
            table: schema.name,
            // Not a gap in this adapter: `p4rs::Pipeline` has no
            // default-action setter, so the miss action is whatever the `.p4`
            // compiled in. Saying so beats silently accepting a write that
            // would not take effect.
            reason: "the x4c backend compiles `default_action` in; it cannot be changed at run time",
        })
    }
}

/// The `default_action` each shipped table declares in its `.p4`.
fn default_action_of(schema: &'static TableSchema) -> &'static str {
    match schema.name {
        "mac_dst" => "broadcast",
        "ipv4_lpm" => "drop",
        other => panic!("no recorded default action for table `{other}`"),
    }
}

fn describe(schema: &'static TableSchema, e: &Live) -> EntryDesc {
    let action = schema.action(e.action).expect("action is from the schema");
    EntryDesc {
        key: key_id(&e.key),
        action: e.action.to_owned(),
        params: action
            .params
            .iter()
            .zip(&e.params)
            .map(|(p, v)| (p.name.to_owned(), v.to_string()))
            .collect(),
    }
}

/// One shard's private pipeline, plus its position in the shared journal.
struct X4cEngine {
    desc: &'static Desc,
    journal: Arc<Shared<Journal>>,
    pipe: Box<dyn p4rs::Pipeline>,
    radix: u16,
    generation: u64,
    applied: usize,
    version: u64,
    scratch_in: Vec<u8>,
    scratch_out: Vec<u8>,
}

impl X4cEngine {
    /// Bring this shard's private tables up to the published journal.
    ///
    /// Fast path: one `Acquire` load and a compare. The `Arc` clone and the
    /// replay happen only on the frame that first observes a write.
    #[inline]
    fn sync(&mut self, shared: &Shared<Journal>) {
        let version = shared.version();
        if version == self.version {
            return;
        }
        let j: Arc<Journal> = shared.load();
        if j.generation != self.generation {
            // The log was rewritten, so this shard's position in it is
            // meaningless: start from a fresh pipeline and replay all of it.
            self.pipe = (self.desc.new)(self.radix);
            self.generation = j.generation;
            self.applied = 0;
        }
        for op in &j.ops[self.applied..] {
            apply(self.desc, self.pipe.as_mut(), op);
        }
        self.applied = j.ops.len();
        self.version = version;
    }
}

/// Replay one operation into a private pipeline. Deterministic: this is the
/// `apply` of the fold, and every shard runs the same sequence of them.
fn apply(desc: &Desc, pipe: &mut dyn p4rs::Pipeline, op: &Op) {
    match op {
        Op::Add {
            table,
            key,
            action,
            params,
        } => {
            // Remove first. x4c stores entries in a set keyed by the *whole*
            // entry, action included, so adding a second entry for a key that
            // already has one leaves both installed and the older one can win
            // the lookup. up4's `table_add` means install-or-replace, so the
            // removal is what makes replay last-writer-wins and therefore
            // idempotent — which the fold depends on.
            let k = encode_key(*key);
            pipe.remove_table_entry(desc.id(table), k.as_slice());
            pipe.add_table_entry(
                desc.id(table),
                action,
                k.as_slice(),
                encode_params(params).as_slice(),
                0,
            );
        }
        Op::Remove { table, key } => {
            pipe.remove_table_entry(desc.id(table), encode_key(*key).as_slice());
        }
    }
}

impl Engine for X4cEngine {
    fn process(&mut self, f: &mut FrameCtx<'_>) -> Verdict {
        let journal = Arc::clone(&self.journal);
        self.sync(&journal);
        self.run(f)
    }

    fn name(&self) -> &'static str {
        self.desc.name
    }
}

impl X4cEngine {
    fn run(&mut self, f: &mut FrameCtx<'_>) -> Verdict {
        if f.len() < self.desc.min_parse {
            // The parser would reject this; p4rs would panic instead.
            return Verdict::Drop;
        }
        // `packet_out` borrows the input, so the result cannot be written back
        // over the bytes it points at. Two reused buffers, no per-frame
        // allocation *here* — x4c's runtime allocates internally regardless.
        self.scratch_in.clear();
        self.scratch_in.extend_from_slice(f.frame());

        let mut pkt = p4rs::packet_in::new(&self.scratch_in);
        let out = self.pipe.process_packet(0, &mut pkt);

        let verdict = match out.as_slice() {
            [] => Verdict::Drop,
            [(_, port)] if *port == PUNT_PORT => Verdict::Punt,
            [(_, port)] if *port == BROADCAST_PORT => Verdict::Broadcast,
            [(pkt, port)] => {
                self.scratch_out.clear();
                self.scratch_out.extend_from_slice(&pkt.header_data);
                self.scratch_out.extend_from_slice(pkt.payload_data);
                Verdict::Forward(*port)
            }
            // SoftNPU expands replication before returning, so more than one
            // output *is* a broadcast. The frame is identical on every port,
            // so the first one carries the bytes.
            [(pkt, _), ..] => {
                self.scratch_out.clear();
                self.scratch_out.extend_from_slice(&pkt.header_data);
                self.scratch_out.extend_from_slice(pkt.payload_data);
                Verdict::Broadcast
            }
        };
        drop(out);

        if matches!(verdict, Verdict::Drop | Verdict::Punt) {
            return verdict;
        }
        // The frame's length is invariant: these programs deparse exactly the
        // headers they parsed. `packet_out` reports header bytes and payload
        // separately and the two do not always sum to the input length, so the
        // input length is the authority — trusting the sum made a frame in a
        // tight buffer look too long and turned every hit into a drop.
        let len = f.len().min(self.scratch_out.len());
        f.frame_mut()[..len].copy_from_slice(&self.scratch_out[..len]);
        verdict
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use up4_engine::MIN_HEADROOM;
    use up4_engine::{MacAddr, ValKind};

    const DMAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x02];
    const SMAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x01];

    fn params() -> PipelineParams {
        PipelineParams::new([0, 1])
    }

    /// Run one frame through an engine and return the verdict plus the frame
    /// as the pipeline left it.
    fn run(engine: &mut dyn Engine, frame: &[u8]) -> (Verdict, Vec<u8>) {
        let mut buf = vec![0u8; MIN_HEADROOM + 2048];
        buf[MIN_HEADROOM..MIN_HEADROOM + frame.len()].copy_from_slice(frame);
        let mut ctx =
            FrameCtx::new(&mut buf, MIN_HEADROOM, frame.len(), 0, 0).expect("window fits");
        let v = engine.process(&mut ctx);
        (v, ctx.frame().to_vec())
    }

    fn eth(dst: [u8; 6], ethertype: u16) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&dst);
        f.extend_from_slice(&SMAC);
        f.extend_from_slice(&ethertype.to_be_bytes());
        f.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        f
    }

    #[test]
    fn every_schema_has_an_x4c_identifier_and_x4c_agrees() {
        // `Desc::id` is total over `schemas` only if this holds, and the
        // identifiers are the ones the generated code actually answers to.
        for desc in [&L2FWD, &L3FWD] {
            let pipe = (desc.new)(2);
            let known = pipe.get_table_ids();
            for s in desc.schemas {
                let id = desc.id(s.name);
                assert!(
                    known.contains(&id),
                    "{}: x4c knows {known:?}, not {id:?}",
                    desc.name
                );
            }
            assert_eq!(known.len(), desc.schemas.len(), "{}", desc.name);
        }
    }

    #[test]
    fn a_forward_entry_reaches_the_port_it_names() {
        let p = X4cPipeline::l2fwd(&params());
        p.tables()
            .table_add(
                "mac_dst",
                TypedKey::Exact(TypedVal::Mac(MacAddr::new(DMAC))),
                "forward",
                &[TypedVal::U16(1)],
            )
            .expect("install");
        let mut e = p.engine();
        let (v, out) = run(e.as_mut(), &eth(DMAC, 0x0800));
        assert_eq!(v, Verdict::Forward(1));
        assert_eq!(&out[..6], &DMAC, "the frame comes back intact");
    }

    #[test]
    fn a_miss_broadcasts() {
        let p = X4cPipeline::l2fwd(&params());
        let mut e = p.engine();
        let (v, _) = run(e.as_mut(), &eth([0xff; 6], 0x0800));
        assert_eq!(v, Verdict::Broadcast, "l2fwd floods on a miss");
    }

    /// The property the journal exists for: an engine minted *before* a write
    /// converges with one minted after, without either sharing a pipeline.
    #[test]
    fn engines_converge_whenever_they_were_minted() {
        let p = X4cPipeline::l2fwd(&params());
        let mut early = p.engine();

        // Before the write: a miss.
        assert_eq!(
            run(early.as_mut(), &eth(DMAC, 0x0800)).0,
            Verdict::Broadcast
        );

        p.tables()
            .table_add(
                "mac_dst",
                TypedKey::Exact(TypedVal::Mac(MacAddr::new(DMAC))),
                "forward",
                &[TypedVal::U16(1)],
            )
            .expect("install");
        let mut late = p.engine();

        assert_eq!(
            run(early.as_mut(), &eth(DMAC, 0x0800)).0,
            Verdict::Forward(1)
        );
        assert_eq!(
            run(late.as_mut(), &eth(DMAC, 0x0800)).0,
            Verdict::Forward(1)
        );
    }

    #[test]
    fn a_removal_replays_too() {
        let p = X4cPipeline::l2fwd(&params());
        let key = TypedKey::Exact(TypedVal::Mac(MacAddr::new(DMAC)));
        p.tables()
            .table_add("mac_dst", key, "forward", &[TypedVal::U16(1)])
            .expect("install");
        let mut e = p.engine();
        assert_eq!(run(e.as_mut(), &eth(DMAC, 0x0800)).0, Verdict::Forward(1));

        p.tables().table_remove("mac_dst", key).expect("remove");
        assert_eq!(
            run(e.as_mut(), &eth(DMAC, 0x0800)).0,
            Verdict::Broadcast,
            "the same engine sees the removal"
        );
    }

    /// Compaction rewrites the log and bumps the generation; a shard that was
    /// mid-log must rebuild rather than replay from a stale index.
    #[test]
    fn compaction_does_not_lose_state() {
        let p = X4cPipeline::l2fwd(&params());
        let mut e = p.engine();
        let key = TypedKey::Exact(TypedVal::Mac(MacAddr::new(DMAC)));

        // Churn one key enough to force at least one compaction.
        for i in 0..64u16 {
            p.tables()
                .table_add("mac_dst", key, "forward", &[TypedVal::U16(i % 2)])
                .expect("install");
        }
        assert!(
            p.journal.load().generation > 0,
            "the log should have been compacted"
        );
        assert_eq!(p.tables().table_dump("mac_dst").expect("dump").len(), 1);
        // The last write wins. This is the assertion that caught x4c's add
        // being non-replacing: without the remove in `apply`, a stale entry
        // for the same key survives the replay and answers the lookup.
        assert_eq!(run(e.as_mut(), &eth(DMAC, 0x0800)).0, Verdict::Forward(1));
    }

    #[test]
    fn l3fwd_routes_by_longest_prefix_and_decrements_ttl() {
        let p = X4cPipeline::l3fwd(&params());
        p.tables()
            .table_add(
                "ipv4_lpm",
                TypedKey::Lpm {
                    value: TypedVal::Ipv4(Ipv4Addr::new(10, 0, 0, 0)),
                    prefix_len: 8,
                },
                "forward",
                &[TypedVal::U16(1), TypedVal::Mac(MacAddr::new(DMAC))],
            )
            .expect("install");

        let mut frame = eth([0xaa; 6], 0x0800);
        frame.truncate(14);
        // Minimal IPv4 header: dst 10.1.2.3, ttl 64.
        let mut ip = vec![
            0x45, 0x00, 0x00, 0x14, 0, 0, 0, 0, 64, 17, 0, 0, 192, 168, 0, 1, 10, 1, 2, 3,
        ];
        frame.append(&mut ip);

        let mut e = p.engine();
        let (v, out) = run(e.as_mut(), &frame);
        assert_eq!(v, Verdict::Forward(1));
        assert_eq!(&out[..6], &DMAC, "next-hop MAC rewritten");
        assert_eq!(out[14 + 8], 63, "TTL decremented");
        assert_eq!(&out[14 + 10..14 + 12], &[0, 0], "checksum zero-filled");
    }

    #[test]
    fn a_route_miss_drops() {
        let p = X4cPipeline::l3fwd(&params());
        let mut e = p.engine();
        let mut frame = eth([0xaa; 6], 0x0800);
        frame.truncate(14);
        frame.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x14, 0, 0, 0, 0, 64, 17, 0, 0, 192, 168, 0, 1, 10, 1, 2, 3,
        ]);
        assert_eq!(run(e.as_mut(), &frame).0, Verdict::Drop);
    }

    #[test]
    fn the_control_plane_refuses_what_the_schema_refuses() {
        let p = X4cPipeline::l2fwd(&params());
        let t = p.tables();
        assert!(matches!(
            t.table_add("nope", TypedKey::Exact(TypedVal::U16(1)), "forward", &[]),
            Err(TableError::UnknownTable { .. })
        ));
        assert!(matches!(
            t.table_add(
                "mac_dst",
                TypedKey::Exact(TypedVal::U16(1)),
                "forward",
                &[TypedVal::U16(1)]
            ),
            Err(TableError::KeyKindMismatch {
                want: up4_engine::KeyKind::Exact(ValKind::Mac),
                ..
            })
        ));
        assert!(matches!(
            t.table_add(
                "mac_dst",
                TypedKey::Exact(TypedVal::Mac(MacAddr::new(DMAC))),
                "forward",
                &[]
            ),
            Err(TableError::Arity { .. })
        ));
    }

    /// An honest refusal beats silently accepting a write that cannot take
    /// effect: `p4rs::Pipeline` has no default-action setter.
    #[test]
    fn setting_a_default_action_is_refused_with_a_reason() {
        let p = X4cPipeline::l2fwd(&params());
        let err = p
            .tables()
            .table_set_default("mac_dst", "drop", &[])
            .expect_err("x4c compiles the default in");
        assert!(matches!(err, TableError::Unsupported { .. }));
        assert!(err.to_string().contains("run time"), "{err}");
        // …but reading it still works, from the source of record.
        assert_eq!(
            p.tables().table_default("mac_dst").expect("read").action,
            "broadcast"
        );
    }

    #[test]
    fn clearing_a_table_removes_every_entry() {
        let p = X4cPipeline::l2fwd(&params());
        for i in 0..4u8 {
            p.tables()
                .table_add(
                    "mac_dst",
                    TypedKey::Exact(TypedVal::Mac(MacAddr::new([0x02, 0, 0, 0, 0, i]))),
                    "forward",
                    &[TypedVal::U16(1)],
                )
                .expect("install");
        }
        assert_eq!(p.tables().table_dump("mac_dst").expect("dump").len(), 4);
        assert_eq!(p.tables().table_clear("mac_dst").expect("clear"), 4);
        assert!(p.tables().table_dump("mac_dst").expect("dump").is_empty());
    }
}
