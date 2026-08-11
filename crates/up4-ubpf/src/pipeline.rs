//! Adapting the uBPF VM onto up4's `Engine`/`Pipeline`.
//!
//! Unlike the x4c backend, nothing here has to be reconciled: p4c reaches a
//! table through a *host* call, so the tables are already up4's own and sit
//! behind the usual copy-on-write publication. A shard reads a snapshot, the
//! control plane swaps an `Arc`, and the VM only ever sees the value bytes a
//! lookup produced.
//!
//! What this module owns is the translation at the two edges: up4's typed
//! control plane into the C struct images p4c compiled in, and the VM's
//! `output_port` back into a [`Verdict`].
//!
//! Cost: one `Acquire` load and a compare per frame to notice a control-plane
//! write, then the VM's own execution. The frame is copied in and out because
//! the program deparses into the buffer it parsed from.

use std::sync::Arc;

use up4_engine::table::Shared;
use up4_engine::{
    Engine, EntryDesc, FrameCtx, Pipeline, PipelineParams, TableError, TableOps, TableSchema,
    TypedKey, TypedVal, Verdict,
};

use crate::elf;
use crate::table::{Layout, Match, Table};
use crate::vm::Vm;

/// up4's reserved egress ports (spec S5), as the `.ubpf.p4` sources write them.
const PUNT_PORT: u32 = 65535;
const BROADCAST_PORT: u32 = 65534;

/// Largest frame this backend will hand the VM.
const MTU: usize = 2048;

/// One action, as the compiled program encodes it.
struct ActionAbi {
    /// The P4 action name, matching the schema.
    name: &'static str,
    /// Its position in p4c's `enum <table>_0_actions`.
    disc: u32,
    /// Where each parameter sits inside the value image, and how wide it is.
    /// Stated rather than packed: a C union aligns to its widest member, so
    /// `forward(bit<16>, bit<48>)` leaves a hole a formula would fill wrongly.
    fields: &'static [(usize, usize)],
}

/// One table's compiled shape.
struct TableAbi {
    /// Schema name, as up4 and the `.p4` call it.
    name: &'static str,
    matching: Match,
    layout: Layout,
    actions: &'static [ActionAbi],
    /// The `default_action` the `.p4` declares, which p4c compiles into the
    /// table's defaultAction map.
    default: &'static str,
}

/// Everything program-specific, as data.
struct Desc {
    name: &'static str,
    schemas: &'static [TableSchema],
    object: &'static [u8],
    tables: &'static [TableAbi],
}

const L2FWD: Desc = Desc {
    name: "l2fwd/ubpf",
    schemas: up4_engine::programs::l2fwd::SCHEMAS,
    object: include_bytes!("generated/l2fwd.o"),
    tables: &[TableAbi {
        name: "mac_dst",
        matching: Match::Exact,
        // `struct pipe_mac_dst_key { uint64_t hdr_ethernet_dst; }` and
        // `struct pipe_mac_dst_value { enum action; union { uint16_t port } }`.
        layout: Layout::scalar(8, 2),
        actions: &[
            ActionAbi {
                name: "forward",
                disc: 0,
                fields: &[(4, 2)],
            },
            ActionAbi {
                name: "broadcast",
                disc: 1,
                fields: &[],
            },
            ActionAbi {
                name: "drop",
                disc: 2,
                fields: &[],
            },
        ],
        default: "broadcast",
    }],
};

const L3FWD: Desc = Desc {
    name: "l3fwd/ubpf",
    schemas: up4_engine::programs::l3fwd::SCHEMAS,
    object: include_bytes!("generated/l3fwd.o"),
    tables: &[TableAbi {
        name: "ipv4_lpm",
        matching: Match::Lpm,
        // key `{ uint32_t prefix_len0; uint32_t hdr_ipv4_dst; }` — the program
        // zeroes the length and the host matches on the address, so the match
        // window is the second word. The value's union aligns to 8 because it
        // holds a uint64 dmac, so parameters start at 8 and dmac at 16.
        layout: Layout::explicit(8, 24, 8, 4, 4),
        actions: &[
            ActionAbi {
                name: "forward",
                disc: 0,
                fields: &[(8, 2), (16, 8)],
            },
            ActionAbi {
                name: "punt",
                disc: 1,
                fields: &[],
            },
            ActionAbi {
                name: "drop",
                disc: 2,
                fields: &[],
            },
        ],
        default: "drop",
    }],
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

    fn abi(&self, table: &str) -> &'static TableAbi {
        self.tables
            .iter()
            .find(|t| t.name == table)
            .unwrap_or_else(|| panic!("no compiled shape for table `{table}`"))
    }
}

/// A value read as a big-endian number, in the native-endian image p4c stores.
///
/// Settled by experiment (`vm::key_tests`): `aa:bb:cc:dd:ee:ff` on the wire is
/// the integer `0x0000_aabb_ccdd_eeff`. The same rule governs an IPv4 address
/// and an action's `bit<n>` parameter, so it is written once here.
fn as_number(v: TypedVal) -> u64 {
    match v {
        TypedVal::U8(x) => u64::from(x),
        TypedVal::U16(x) => u64::from(x),
        TypedVal::U32(x) => u64::from(x),
        TypedVal::Mac(m) => m
            .octets()
            .iter()
            .fold(0u64, |n, b| (n << 8) | u64::from(*b)),
        TypedVal::Ipv4(a) => u64::from(u32::from_be_bytes(a.octets())),
    }
}

/// Build the key image the compiled program will construct for this value.
fn key_image(abi: &TableAbi, key: TypedKey) -> (Vec<u8>, u8) {
    let mut img = vec![0u8; abi.layout.key];
    let (value, prefix) = match key {
        TypedKey::Exact(v) => (v, 0),
        TypedKey::Lpm { value, prefix_len } => (value, prefix_len),
    };
    let n = as_number(value).to_le_bytes();
    let at = abi.layout.match_at;
    let len = abi.layout.match_len;
    img[at..at + len].copy_from_slice(&n[..len]);
    (img, prefix)
}

/// Build the value image for an action call.
fn value_image(abi: &TableAbi, action: &ActionAbi, params: &[TypedVal]) -> Vec<u8> {
    let mut v = vec![0u8; abi.layout.value];
    v[abi.layout.action_at..abi.layout.action_at + 4].copy_from_slice(&action.disc.to_le_bytes());
    for ((at, width), p) in action.fields.iter().zip(params) {
        let n = as_number(*p).to_le_bytes();
        v[*at..*at + width].copy_from_slice(&n[..*width]);
    }
    v
}

/// A loaded uBPF pipeline.
pub struct UbpfPipeline {
    desc: &'static Desc,
    program: elf::Program,
    tables: Arc<Shared<Vec<Table>>>,
}

impl UbpfPipeline {
    fn new(desc: &'static Desc) -> Self {
        let program = elf::load(desc.object)
            .unwrap_or_else(|e| panic!("{}: committed object does not load: {e}", desc.name));
        // One `Table` per map the program refers to, in index order — the
        // order the loader baked into the instruction stream.
        let tables: Vec<Table> = program
            .maps
            .iter()
            .map(|m| {
                let abi = desc.abi(&m.table);
                if m.is_default {
                    // p4c's defaultAction map is an array of one with a uint32
                    // key; it always answers, with the `.p4`'s default action.
                    let d = Layout::explicit(4, abi.layout.value, abi.layout.params_at, 0, 4);
                    let act = abi
                        .actions
                        .iter()
                        .find(|a| a.name == abi.default)
                        .unwrap_or_else(|| panic!("{} has no action {}", abi.name, abi.default));
                    Table::new(Match::Exact, d, Some(value_image(abi, act, &[])))
                } else {
                    Table::new(abi.matching, abi.layout, None)
                }
            })
            .collect();
        Self {
            desc,
            program,
            tables: Arc::new(Shared::new(tables)),
        }
    }

    /// The `l2fwd` program on this backend.
    #[must_use]
    pub fn l2fwd(_params: &PipelineParams) -> Self {
        Self::new(&L2FWD)
    }

    /// The `l3fwd` program on this backend.
    #[must_use]
    pub fn l3fwd(_params: &PipelineParams) -> Self {
        Self::new(&L3FWD)
    }

    /// Index of the entry map for `table`, which is where writes land.
    fn entry_map(&self, table: &str) -> usize {
        self.program
            .maps
            .iter()
            .position(|m| m.table == table && !m.is_default)
            .unwrap_or_else(|| panic!("no entry map for `{table}`"))
    }

    fn default_map(&self, table: &str) -> usize {
        self.program
            .maps
            .iter()
            .position(|m| m.table == table && m.is_default)
            .unwrap_or_else(|| panic!("no default map for `{table}`"))
    }
}

impl Pipeline for UbpfPipeline {
    fn name(&self) -> &'static str {
        self.desc.name
    }

    fn engine(&self) -> Box<dyn Engine> {
        Box::new(UbpfEngine {
            desc: self.desc,
            vm: Vm::new(&self.program, MTU).unwrap_or_else(|e| {
                panic!(
                    "{}: VM would not accept its own bytecode: {e}",
                    self.desc.name
                )
            }),
            tables: Arc::clone(&self.tables),
            snapshot: self.tables.load(),
            version: self.tables.version(),
        })
    }

    fn tables(&self) -> &dyn TableOps {
        self
    }
}

impl TableOps for UbpfPipeline {
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
        schema.check(action, params)?;
        let abi = self.desc.abi(schema.name);
        let act = abi
            .actions
            .iter()
            .find(|a| a.name == action)
            .ok_or_else(|| TableError::UnknownAction {
                table: schema.name,
                action: action.to_owned(),
                known: abi.actions.iter().map(|a| a.name.to_owned()).collect(),
            })?;
        let (img, prefix) = key_image(abi, key);
        let value = value_image(abi, act, params);
        let idx = self.entry_map(schema.name);
        self.tables.update(|t| {
            let mut next = t.clone();
            next[idx].insert(&img, prefix, value.clone());
            (next, ())
        });
        Ok(())
    }

    fn table_remove(&self, table: &str, key: TypedKey) -> Result<(), TableError> {
        let schema = self.desc.schema(table)?;
        schema.check_key(&key)?;
        let abi = self.desc.abi(schema.name);
        let (img, prefix) = key_image(abi, key);
        let idx = self.entry_map(schema.name);
        self.tables.update(|t| {
            let mut next = t.clone();
            next[idx].remove(&img, prefix);
            (next, ())
        });
        Ok(())
    }

    fn table_clear(&self, table: &str) -> Result<usize, TableError> {
        let schema = self.desc.schema(table)?;
        let idx = self.entry_map(schema.name);
        Ok(self.tables.update(|t| {
            let mut next = t.clone();
            let n = next[idx].clear();
            (next, n)
        }))
    }

    fn table_dump(&self, table: &str) -> Result<Vec<EntryDesc>, TableError> {
        let schema = self.desc.schema(table)?;
        let abi = self.desc.abi(schema.name);
        let idx = self.entry_map(schema.name);
        let snap = self.tables.load();
        Ok(snap[idx]
            .iter()
            .map(|(prefix, k, v)| describe(schema, abi, prefix, k, v))
            .collect())
    }

    fn table_default(&self, table: &str) -> Result<EntryDesc, TableError> {
        let schema = self.desc.schema(table)?;
        let abi = self.desc.abi(schema.name);
        let idx = self.default_map(schema.name);
        let snap = self.tables.load();
        let v = snap[idx].lookup(&[0; 8]).unwrap_or(&[]).to_vec();
        Ok(EntryDesc {
            key: "*".to_owned(),
            action: action_of(abi, &v).unwrap_or(abi.default).to_owned(),
            params: std::collections::BTreeMap::new(),
        })
    }

    fn table_set_default(
        &self,
        table: &str,
        action: &str,
        params: &[TypedVal],
    ) -> Result<(), TableError> {
        let schema = self.desc.schema(table)?;
        schema.check(action, params)?;
        let abi = self.desc.abi(schema.name);
        let act = abi
            .actions
            .iter()
            .find(|a| a.name == action)
            .ok_or_else(|| TableError::UnknownAction {
                table: schema.name,
                action: action.to_owned(),
                known: abi.actions.iter().map(|a| a.name.to_owned()).collect(),
            })?;
        let value = value_image(abi, act, params);
        let idx = self.default_map(schema.name);
        // Unlike x4c, this backend *can* change a miss action: p4c compiles the
        // default into a map, and the map is ours.
        self.tables.update(|t| {
            let mut next = t.clone();
            next[idx].set_default(value.clone());
            (next, ())
        });
        Ok(())
    }
}

fn action_of(abi: &TableAbi, value: &[u8]) -> Option<&'static str> {
    let disc = u32::from_le_bytes(value.get(0..4)?.try_into().ok()?);
    abi.actions.iter().find(|a| a.disc == disc).map(|a| a.name)
}

fn describe(
    schema: &'static TableSchema,
    abi: &TableAbi,
    prefix: u8,
    key: &[u8],
    value: &[u8],
) -> EntryDesc {
    let n = key
        .iter()
        .rev()
        .fold(0u64, |acc, b| (acc << 8) | u64::from(*b));
    let key_text = match abi.matching {
        Match::Exact => format!("{n:#x}"),
        Match::Lpm => format!("{n:#x}/{prefix}"),
    };
    let action = action_of(abi, value).unwrap_or("?");
    let params = schema
        .action(action)
        .map(|a| {
            a.params
                .iter()
                .zip(
                    abi.actions
                        .iter()
                        .find(|x| x.name == action)
                        .map_or(&[][..], |x| x.fields),
                )
                .map(|(p, (at, w))| {
                    let raw = value
                        .get(*at..*at + *w)
                        .map(|s| {
                            s.iter()
                                .rev()
                                .fold(0u64, |acc, b| (acc << 8) | u64::from(*b))
                        })
                        .unwrap_or_default();
                    (p.name.to_owned(), raw.to_string())
                })
                .collect()
        })
        .unwrap_or_default();
    EntryDesc {
        key: key_text,
        action: action.to_owned(),
        params,
    }
}

/// One shard's VM plus its view of the published tables.
struct UbpfEngine {
    desc: &'static Desc,
    vm: Vm,
    tables: Arc<Shared<Vec<Table>>>,
    snapshot: Arc<Vec<Table>>,
    version: u64,
}

impl Engine for UbpfEngine {
    fn process(&mut self, f: &mut FrameCtx<'_>) -> Verdict {
        // One Acquire load and a compare; the `Arc` clone happens only on the
        // frame that first observes a control-plane write.
        let version = self.tables.version();
        if version != self.version {
            self.snapshot = self.tables.load();
            self.version = version;
        }

        let Ok(out) = self.vm.run(f.frame(), f.ingress_vport, &self.snapshot) else {
            // A refused helper or a VM fault is a pipeline decision to drop,
            // not a harness error: the frame is accounted for either way.
            return Verdict::Drop;
        };
        // A parser rejection returns the same code as a pass and leaves the
        // port untouched, so both have to be checked.
        if !out.pass || out.output_port == crate::vm::NO_PORT {
            return Verdict::Drop;
        }
        match out.output_port {
            PUNT_PORT => Verdict::Punt,
            BROADCAST_PORT => Verdict::Broadcast,
            port => {
                // The frame's length is invariant: `ubpf_adjust_head` with a
                // non-zero delta is refused, so the deparser rewrites headers
                // in place and cannot resize. `std_meta.packet_length` is *not*
                // that length — p4c adds the deparsed header size to it — so
                // trusting it would grow every frame by its own header and
                // make a tight buffer look too small.
                let len = f.len();
                f.frame_mut().copy_from_slice(&self.vm.packet()[..len]);
                #[allow(clippy::cast_possible_truncation)]
                Verdict::Forward(port as u16)
            }
        }
    }

    fn name(&self) -> &'static str {
        self.desc.name
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use up4_engine::MIN_HEADROOM;
    use up4_engine::MacAddr;

    const DMAC: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

    fn params() -> PipelineParams {
        PipelineParams::new([0, 1])
    }

    fn run(e: &mut dyn Engine, frame: &[u8]) -> (Verdict, Vec<u8>) {
        let mut buf = vec![0u8; MIN_HEADROOM + 2048];
        buf[MIN_HEADROOM..MIN_HEADROOM + frame.len()].copy_from_slice(frame);
        let mut ctx =
            FrameCtx::new(&mut buf, MIN_HEADROOM, frame.len(), 0, 0).expect("window fits");
        let v = e.process(&mut ctx);
        (v, ctx.frame().to_vec())
    }

    fn eth(dst: [u8; 6]) -> Vec<u8> {
        let mut f = dst.to_vec();
        f.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x01]);
        f.extend_from_slice(&0x0800u16.to_be_bytes());
        f.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        f
    }

    #[test]
    fn l2fwd_forwards_to_the_port_its_table_names() {
        let p = UbpfPipeline::l2fwd(&params());
        p.tables()
            .table_add(
                "mac_dst",
                TypedKey::Exact(TypedVal::Mac(MacAddr::new(DMAC))),
                "forward",
                &[TypedVal::U16(1)],
            )
            .expect("install");
        let mut e = p.engine();
        assert_eq!(run(e.as_mut(), &eth(DMAC)).0, Verdict::Forward(1));
    }

    #[test]
    fn l2fwd_broadcasts_on_a_miss() {
        let p = UbpfPipeline::l2fwd(&params());
        let mut e = p.engine();
        assert_eq!(run(e.as_mut(), &eth([0x11; 6])).0, Verdict::Broadcast);
    }

    /// The published-snapshot property: an engine minted before a write sees
    /// it, without the pipeline being mutable.
    #[test]
    fn a_live_engine_sees_a_later_write() {
        let p = UbpfPipeline::l2fwd(&params());
        let mut e = p.engine();
        assert_eq!(run(e.as_mut(), &eth(DMAC)).0, Verdict::Broadcast);
        p.tables()
            .table_add(
                "mac_dst",
                TypedKey::Exact(TypedVal::Mac(MacAddr::new(DMAC))),
                "forward",
                &[TypedVal::U16(1)],
            )
            .expect("install");
        assert_eq!(run(e.as_mut(), &eth(DMAC)).0, Verdict::Forward(1));
    }

    /// Unlike x4c, this backend can change a miss action: p4c compiles the
    /// default into a map, and the map is ours.
    #[test]
    fn the_default_action_can_be_replaced() {
        let p = UbpfPipeline::l2fwd(&params());
        let mut e = p.engine();
        assert_eq!(run(e.as_mut(), &eth([0x11; 6])).0, Verdict::Broadcast);
        p.tables()
            .table_set_default("mac_dst", "drop", &[])
            .expect("set default");
        assert_eq!(run(e.as_mut(), &eth([0x11; 6])).0, Verdict::Drop);
    }

    fn ipv4(dst: Ipv4Addr, ttl: u8) -> Vec<u8> {
        let mut f = vec![0x11; 6];
        f.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x01]);
        f.extend_from_slice(&0x0800u16.to_be_bytes());
        f.extend_from_slice(&[0x45, 0x00, 0x00, 0x14, 0, 0, 0, 0, ttl, 17, 0, 0]);
        f.extend_from_slice(&Ipv4Addr::new(192, 168, 0, 1).octets());
        f.extend_from_slice(&dst.octets());
        f
    }

    #[test]
    fn l3fwd_routes_by_longest_prefix_and_rewrites_the_frame() {
        let p = UbpfPipeline::l3fwd(&params());
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
        let mut e = p.engine();
        let (v, out) = run(e.as_mut(), &ipv4(Ipv4Addr::new(10, 1, 2, 3), 64));
        assert_eq!(v, Verdict::Forward(1));
        assert_eq!(&out[..6], &DMAC, "next-hop MAC rewritten");
        assert_eq!(out[14 + 8], 63, "TTL decremented");
        assert_eq!(&out[14 + 10..14 + 12], &[0, 0], "checksum zero-filled");
    }

    #[test]
    fn l3fwd_drops_an_unrouted_destination_and_an_expired_ttl() {
        let p = UbpfPipeline::l3fwd(&params());
        let mut e = p.engine();
        assert_eq!(
            run(e.as_mut(), &ipv4(Ipv4Addr::new(10, 1, 2, 3), 64)).0,
            Verdict::Drop,
            "no route: the compiled default action is drop"
        );
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
        assert_eq!(
            run(e.as_mut(), &ipv4(Ipv4Addr::new(10, 1, 2, 3), 0)).0,
            Verdict::Drop,
            "TTL 0 arrives already expired"
        );
    }

    #[test]
    fn punt_reaches_the_control_channel() {
        let p = UbpfPipeline::l3fwd(&params());
        p.tables()
            .table_add(
                "ipv4_lpm",
                TypedKey::Lpm {
                    value: TypedVal::Ipv4(Ipv4Addr::new(10, 0, 0, 0)),
                    prefix_len: 8,
                },
                "punt",
                &[],
            )
            .expect("install");
        let mut e = p.engine();
        assert_eq!(
            run(e.as_mut(), &ipv4(Ipv4Addr::new(10, 1, 2, 3), 64)).0,
            Verdict::Punt
        );
    }

    #[test]
    fn the_control_plane_refuses_what_the_schema_refuses() {
        let p = UbpfPipeline::l2fwd(&params());
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
            Err(TableError::KeyKindMismatch { .. })
        ));
    }

    #[test]
    fn dump_and_clear_report_what_is_installed() {
        let p = UbpfPipeline::l2fwd(&params());
        for i in 0..3u8 {
            p.tables()
                .table_add(
                    "mac_dst",
                    TypedKey::Exact(TypedVal::Mac(MacAddr::new([0x02, 0, 0, 0, 0, i]))),
                    "forward",
                    &[TypedVal::U16(1)],
                )
                .expect("install");
        }
        let d = p.tables().table_dump("mac_dst").expect("dump");
        assert_eq!(d.len(), 3);
        assert!(d.iter().all(|e| e.action == "forward"));
        assert_eq!(p.tables().table_clear("mac_dst").expect("clear"), 3);
        assert!(p.tables().table_dump("mac_dst").expect("dump").is_empty());
    }
}
