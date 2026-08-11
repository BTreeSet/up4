//! `l2fwd`: an L2 switch with a static forwarding database.
//!
//! Rendering of `p4/programs/l2fwd/l2fwd.p4`:
//!
//! ```text
//! parser        extract ethernet                      -> Ethernet::parse
//! table mac_dst key   = { hdr.ethernet.dst : exact }  -> ExactTable<MacAddr, _>
//!               actions = { forward; broadcast; drop }
//!               default_action = broadcast            -> ExactTable default
//! ```
//!
//! The program modifies no header, so nothing is deparsed and no checksum is
//! zeroed: there is nothing stale to hide (spec S1.5 applies "whenever the
//! pipeline modifies the containing header").
//!
//! Cost: one hashed probe per frame, no allocation.

use crate::{
    Engine, FrameCtx, Pipeline, PipelineParams, Verdict,
    headers::Ethernet,
    programs::{exact_mac, param_u16},
    shim::{
        ActionSchema, EntryDesc, KeyKind, ParamSchema, TableError, TableOps, TableSchema, TypedKey,
    },
    table::{Cached, ExactTable, Shared},
    value::{MacAddr, TypedVal, ValKind},
};
use std::{collections::BTreeMap, sync::Arc};

/// Registered name.
pub const NAME: &str = "l2fwd";

/// The table's control-plane contract.
pub const SCHEMAS: &[TableSchema] = &[TableSchema {
    name: "mac_dst",
    key_field: "ethernet.dst",
    key: KeyKind::Exact(ValKind::Mac),
    actions: &[
        ActionSchema {
            name: "forward",
            params: &[ParamSchema {
                name: "port",
                kind: ValKind::U16,
            }],
        },
        ActionSchema {
            name: "broadcast",
            params: &[],
        },
        ActionSchema {
            name: "drop",
            params: &[],
        },
    ],
}];

/// The actions `mac_dst` may run — the P4 `actions = { ... }` list, closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Action {
    Forward(u16),
    Broadcast,
    Drop,
}

impl Action {
    /// Build the action a control-plane call names, after the schema has
    /// checked its arity and parameter kinds.
    fn from_call(
        schema: &'static TableSchema,
        action: &str,
        params: &[TypedVal],
    ) -> Result<Self, TableError> {
        let sig = schema.check(action, params)?;
        Ok(match sig.name {
            "forward" => Self::Forward(param_u16(schema, sig.name, params, 0)?),
            "broadcast" => Self::Broadcast,
            // Exhaustive over `SCHEMAS`: `check` refused anything else.
            _ => Self::Drop,
        })
    }

    fn describe(self, key: String) -> EntryDesc {
        let (action, params) = match self {
            Self::Forward(port) => (
                "forward",
                BTreeMap::from([("port".to_owned(), port.to_string())]),
            ),
            Self::Broadcast => ("broadcast", BTreeMap::new()),
            Self::Drop => ("drop", BTreeMap::new()),
        };
        EntryDesc {
            key,
            action: action.to_owned(),
            params,
        }
    }

    const fn verdict(self) -> Verdict {
        match self {
            Self::Forward(port) => Verdict::Forward(port),
            Self::Broadcast => Verdict::Broadcast,
            Self::Drop => Verdict::Drop,
        }
    }
}

type Fdb = ExactTable<MacAddr, Action>;

/// The loaded `l2fwd` program.
#[derive(Debug)]
pub struct L2Fwd {
    mac_dst: Arc<Shared<Fdb>>,
}

impl L2Fwd {
    /// Load the program. The forwarding database starts empty, so every frame
    /// broadcasts until the control plane says otherwise.
    #[must_use]
    pub fn new(_params: &PipelineParams) -> Self {
        Self {
            mac_dst: Arc::new(Shared::new(ExactTable::new(Action::Broadcast))),
        }
    }

    fn schema(&self, table: &str) -> Result<&'static TableSchema, TableError> {
        TableOps::schema(self, table)
    }
}

impl Pipeline for L2Fwd {
    fn name(&self) -> &'static str {
        NAME
    }

    fn engine(&self) -> Box<dyn Engine> {
        Box::new(L2Engine {
            mac_dst: Cached::new(&self.mac_dst),
            shared: Arc::clone(&self.mac_dst),
        })
    }

    fn tables(&self) -> &dyn TableOps {
        self
    }
}

impl TableOps for L2Fwd {
    fn schemas(&self) -> &'static [TableSchema] {
        SCHEMAS
    }

    fn table_add(
        &self,
        table: &str,
        key: TypedKey,
        action: &str,
        params: &[TypedVal],
    ) -> Result<(), TableError> {
        let schema = self.schema(table)?;
        let mac = exact_mac(schema, key)?;
        let action = Action::from_call(schema, action, params)?;
        self.mac_dst.update(|t| {
            let mut next = t.clone();
            next.insert(mac, action);
            (next, ())
        });
        Ok(())
    }

    fn table_remove(&self, table: &str, key: TypedKey) -> Result<(), TableError> {
        let schema = self.schema(table)?;
        let mac = exact_mac(schema, key)?;
        self.mac_dst
            .update(|t| {
                let mut next = t.clone();
                let removed = next.remove(&mac);
                (next, removed)
            })
            .then_some(())
            .ok_or(TableError::NotFound {
                table: schema.name,
                key: mac.to_string(),
            })
    }

    fn table_dump(&self, table: &str) -> Result<Vec<EntryDesc>, TableError> {
        self.schema(table)?;
        let fdb = self.mac_dst.load();
        let mut entries: Vec<EntryDesc> = fdb
            .iter()
            .map(|(mac, a)| a.describe(mac.to_string()))
            .collect();
        entries.sort_by(|a, b| a.key.cmp(&b.key));
        Ok(entries)
    }

    fn table_default(&self, table: &str) -> Result<EntryDesc, TableError> {
        self.schema(table)?;
        Ok(self
            .mac_dst
            .load()
            .default_action()
            .describe("*".to_owned()))
    }

    fn table_set_default(
        &self,
        table: &str,
        action: &str,
        params: &[TypedVal],
    ) -> Result<(), TableError> {
        let schema = self.schema(table)?;
        let action = Action::from_call(schema, action, params)?;
        self.mac_dst.update(|t| {
            let mut next = t.clone();
            next.set_default(action);
            (next, ())
        });
        Ok(())
    }

    fn table_clear(&self, table: &str) -> Result<usize, TableError> {
        self.schema(table)?;
        Ok(self.mac_dst.update(|t| {
            let mut next = t.clone();
            let n = next.clear();
            (next, n)
        }))
    }
}

/// One shard's view of `l2fwd`.
#[derive(Debug)]
struct L2Engine {
    shared: Arc<Shared<Fdb>>,
    mac_dst: Cached<Fdb>,
}

impl Engine for L2Engine {
    #[inline]
    fn process(&mut self, f: &mut FrameCtx<'_>) -> Verdict {
        // parser: a frame too short to hold an Ethernet header extracts
        // nothing, and P4's parser reject means drop.
        let Some(eth) = Ethernet::parse(f.frame()) else {
            return Verdict::Drop;
        };
        self.mac_dst.get(&self.shared).apply(&eth.dst).verdict()
    }

    fn name(&self) -> &'static str {
        NAME
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::headers::ETH_HDR_LEN;

    fn mac(s: &str) -> MacAddr {
        s.parse().expect("literal")
    }

    fn frame_to(dst: &str) -> Vec<u8> {
        let mut f = vec![0u8; ETH_HDR_LEN + 46];
        f[0..6].copy_from_slice(&mac(dst).octets());
        f[6..12].copy_from_slice(&mac("aa:00:00:00:00:ff").octets());
        f
    }

    fn run(engine: &mut dyn Engine, frame: &mut [u8], ingress: u16) -> Verdict {
        let mut buf = vec![0u8; 64 + frame.len()];
        buf[64..].copy_from_slice(frame);
        let mut ctx = FrameCtx::new(&mut buf, 64, frame.len(), ingress, 0).expect("fits");
        let v = engine.process(&mut ctx);
        frame.copy_from_slice(ctx.frame());
        v
    }

    fn loaded() -> (L2Fwd, Box<dyn Engine>) {
        let p = L2Fwd::new(&PipelineParams::new([0, 1]));
        let e = p.engine();
        (p, e)
    }

    #[test]
    fn a_miss_broadcasts() {
        let (_p, mut e) = loaded();
        assert_eq!(
            run(&mut *e, &mut frame_to("aa:bb:cc:dd:ee:01"), 0),
            Verdict::Broadcast
        );
    }

    #[test]
    fn a_hit_forwards_to_the_installed_port() {
        let (p, mut e) = loaded();
        p.table_add(
            "mac_dst",
            TypedKey::parse(SCHEMAS[0].key, "aa:bb:cc:dd:ee:01").expect("valid"),
            "forward",
            &[TypedVal::U16(1)],
        )
        .expect("install");
        assert_eq!(
            run(&mut *e, &mut frame_to("aa:bb:cc:dd:ee:01"), 0),
            Verdict::Forward(1)
        );
        assert_eq!(
            run(&mut *e, &mut frame_to("aa:bb:cc:dd:ee:02"), 0),
            Verdict::Broadcast,
            "other addresses still miss"
        );
    }

    #[test]
    fn a_truncated_frame_is_dropped_by_the_parser() {
        let (_p, mut e) = loaded();
        let mut short = vec![0u8; ETH_HDR_LEN - 1];
        assert_eq!(run(&mut *e, &mut short, 0), Verdict::Drop);
    }

    #[test]
    fn the_pipeline_never_modifies_the_frame() {
        let (p, mut e) = loaded();
        p.table_add(
            "mac_dst",
            TypedKey::parse(SCHEMAS[0].key, "aa:bb:cc:dd:ee:01").expect("valid"),
            "forward",
            &[TypedVal::U16(1)],
        )
        .expect("install");
        let mut f = frame_to("aa:bb:cc:dd:ee:01");
        let before = f.clone();
        run(&mut *e, &mut f, 0);
        assert_eq!(f, before);
    }

    #[test]
    fn control_plane_round_trip() {
        let (p, _e) = loaded();
        let key = TypedKey::parse(SCHEMAS[0].key, "aa:bb:cc:dd:ee:01").expect("valid");
        assert_eq!(p.table_dump("mac_dst").expect("known table"), vec![]);
        assert_eq!(
            p.table_default("mac_dst").expect("known table").action,
            "broadcast"
        );

        p.table_add("mac_dst", key, "forward", &[TypedVal::U16(3)])
            .expect("install");
        let dump = p.table_dump("mac_dst").expect("known table");
        assert_eq!(dump.len(), 1);
        assert_eq!(dump[0].key, "aa:bb:cc:dd:ee:01");
        assert_eq!(dump[0].action, "forward");
        assert_eq!(dump[0].params["port"], "3");

        p.table_set_default("mac_dst", "drop", &[])
            .expect("set default");
        assert_eq!(
            p.table_default("mac_dst").expect("known table").action,
            "drop"
        );

        p.table_remove("mac_dst", key).expect("remove");
        assert_eq!(
            p.table_remove("mac_dst", key),
            Err(TableError::NotFound {
                table: "mac_dst",
                key: "aa:bb:cc:dd:ee:01".into()
            })
        );
        assert_eq!(p.table_clear("mac_dst"), Ok(0));
    }

    #[test]
    fn control_plane_refuses_a_key_of_the_wrong_shape() {
        let (p, _e) = loaded();
        let wrong = TypedKey::parse(KeyKind::Exact(ValKind::U16), "1").expect("valid");
        assert!(matches!(
            p.table_add("mac_dst", wrong, "broadcast", &[]),
            Err(TableError::KeyKindMismatch {
                table: "mac_dst",
                ..
            })
        ));
        assert!(matches!(
            p.table_dump("nope"),
            Err(TableError::UnknownTable { .. })
        ));
    }

    #[test]
    fn a_control_plane_change_is_visible_to_a_running_engine() {
        let (p, mut e) = loaded();
        let key = TypedKey::parse(SCHEMAS[0].key, "aa:bb:cc:dd:ee:01").expect("valid");
        assert_eq!(
            run(&mut *e, &mut frame_to("aa:bb:cc:dd:ee:01"), 0),
            Verdict::Broadcast
        );
        p.table_add("mac_dst", key, "forward", &[TypedVal::U16(2)])
            .expect("install");
        assert_eq!(
            run(&mut *e, &mut frame_to("aa:bb:cc:dd:ee:01"), 0),
            Verdict::Forward(2)
        );
        p.table_remove("mac_dst", key).expect("remove");
        assert_eq!(
            run(&mut *e, &mut frame_to("aa:bb:cc:dd:ee:01"), 0),
            Verdict::Broadcast
        );
    }
}
