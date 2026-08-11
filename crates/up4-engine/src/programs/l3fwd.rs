//! `l3fwd`: an IPv4 router.
//!
//! Rendering of `p4/programs/l3fwd/l3fwd.p4`:
//!
//! ```text
//! parser          extract ethernet                         -> Ethernet::parse
//!                 select(ethertype) 0x0800: extract ipv4   -> Ipv4::parse
//! control ingress if (ipv4.ttl == 0) drop                  -> the TTL guard
//!                 ipv4_lpm.apply()
//! table ipv4_lpm  key     = { hdr.ipv4.dst : lpm }         -> LpmTable<_>
//!                 actions = { forward; punt; drop }
//!                 default_action = drop                    -> LpmTable default
//! action forward(port, dmac)  ipv4.ttl = ipv4.ttl - 1
//!                             ethernet.dst = dmac
//! deparser        emit ethernet, ipv4                      -> in place
//! ```
//!
//! Because `forward` rewrites the IPv4 header, the inner checksums are
//! zero-filled on that path and only that path (spec S1.5): a frame that is
//! dropped or punted leaves the switch untouched, and a frame that is forwarded
//! carries no checksum that pretends to describe its new TTL.
//!
//! The source MAC is deliberately not rewritten: up4 vports have no MAC
//! addresses of their own, and inventing one would be a forwarding decision
//! made outside the pipeline (spec S1.3).
//!
//! Cost: one hashed probe per populated prefix length, no allocation.

use crate::{
    Engine, FrameCtx, Pipeline, PipelineParams, Verdict,
    headers::{ETH_HDR_LEN, ETHERTYPE_IPV4, Ethernet, Ipv4, zero_inner_checksums},
    programs::{lpm_ipv4, param_mac, param_u16},
    shim::{
        ActionSchema, EntryDesc, KeyKind, ParamSchema, TableError, TableOps, TableSchema, TypedKey,
    },
    table::{Cached, LpmTable, Shared},
    value::{MacAddr, TypedVal, ValKind},
};
use std::{collections::BTreeMap, sync::Arc};

/// Registered name.
pub const NAME: &str = "l3fwd";

/// The table's control-plane contract.
pub const SCHEMAS: &[TableSchema] = &[TableSchema {
    name: "ipv4_lpm",
    key_field: "ipv4.dst",
    key: KeyKind::Lpm(ValKind::Ipv4),
    actions: &[
        ActionSchema {
            name: "forward",
            params: &[
                ParamSchema {
                    name: "port",
                    kind: ValKind::U16,
                },
                ParamSchema {
                    name: "dmac",
                    kind: ValKind::Mac,
                },
            ],
        },
        ActionSchema {
            name: "punt",
            params: &[],
        },
        ActionSchema {
            name: "drop",
            params: &[],
        },
    ],
}];

/// The actions `ipv4_lpm` may run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Action {
    Forward { port: u16, dmac: MacAddr },
    Punt,
    Drop,
}

impl Action {
    fn from_call(
        schema: &'static TableSchema,
        action: &str,
        params: &[TypedVal],
    ) -> Result<Self, TableError> {
        let sig = schema.check(action, params)?;
        Ok(match sig.name {
            "forward" => Self::Forward {
                port: param_u16(schema, sig.name, params, 0)?,
                dmac: param_mac(schema, sig.name, params, 1)?,
            },
            "punt" => Self::Punt,
            // Exhaustive over `SCHEMAS`: `check` refused anything else.
            _ => Self::Drop,
        })
    }

    fn describe(self, key: String) -> EntryDesc {
        let (action, params) = match self {
            Self::Forward { port, dmac } => (
                "forward",
                BTreeMap::from([
                    ("port".to_owned(), port.to_string()),
                    ("dmac".to_owned(), dmac.to_string()),
                ]),
            ),
            Self::Punt => ("punt", BTreeMap::new()),
            Self::Drop => ("drop", BTreeMap::new()),
        };
        EntryDesc {
            key,
            action: action.to_owned(),
            params,
        }
    }
}

type Routes = LpmTable<Action>;

/// The loaded `l3fwd` program.
#[derive(Debug)]
pub struct L3Fwd {
    ipv4_lpm: Arc<Shared<Routes>>,
}

impl L3Fwd {
    /// Load the program. With no routes installed every frame is dropped, and
    /// `engine_drop` says so.
    #[must_use]
    pub fn new(_params: &PipelineParams) -> Self {
        Self {
            ipv4_lpm: Arc::new(Shared::new(LpmTable::new(Action::Drop))),
        }
    }

    fn schema(&self, table: &str) -> Result<&'static TableSchema, TableError> {
        TableOps::schema(self, table)
    }
}

impl Pipeline for L3Fwd {
    fn name(&self) -> &'static str {
        NAME
    }

    fn engine(&self) -> Box<dyn Engine> {
        Box::new(L3Engine {
            ipv4_lpm: Cached::new(&self.ipv4_lpm),
            shared: Arc::clone(&self.ipv4_lpm),
        })
    }

    fn tables(&self) -> &dyn TableOps {
        self
    }
}

impl TableOps for L3Fwd {
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
        let prefix = lpm_ipv4(schema, key)?;
        let action = Action::from_call(schema, action, params)?;
        self.ipv4_lpm.update(|t| {
            let mut next = t.clone();
            next.insert(prefix, action);
            (next, ())
        });
        Ok(())
    }

    fn table_remove(&self, table: &str, key: TypedKey) -> Result<(), TableError> {
        let schema = self.schema(table)?;
        let prefix = lpm_ipv4(schema, key)?;
        self.ipv4_lpm
            .update(|t| {
                let mut next = t.clone();
                let removed = next.remove(prefix);
                (next, removed)
            })
            .then_some(())
            .ok_or(TableError::NotFound {
                table: schema.name,
                key: prefix.to_string(),
            })
    }

    fn table_dump(&self, table: &str) -> Result<Vec<EntryDesc>, TableError> {
        self.schema(table)?;
        let routes = self.ipv4_lpm.load();
        // Longest prefix first, then by address: the order a routing table is
        // read in, and deterministic for tests.
        let mut entries: Vec<(u8, std::net::Ipv4Addr, EntryDesc)> = routes
            .iter()
            .map(|(p, a)| (p.prefix_len(), p.addr(), a.describe(p.to_string())))
            .collect();
        entries.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        Ok(entries.into_iter().map(|(_, _, e)| e).collect())
    }

    fn table_default(&self, table: &str) -> Result<EntryDesc, TableError> {
        self.schema(table)?;
        Ok(self
            .ipv4_lpm
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
        self.ipv4_lpm.update(|t| {
            let mut next = t.clone();
            next.set_default(action);
            (next, ())
        });
        Ok(())
    }

    fn table_clear(&self, table: &str) -> Result<usize, TableError> {
        self.schema(table)?;
        Ok(self.ipv4_lpm.update(|t| {
            let mut next = t.clone();
            let n = next.clear();
            (next, n)
        }))
    }
}

/// One shard's view of `l3fwd`.
#[derive(Debug)]
struct L3Engine {
    shared: Arc<Shared<Routes>>,
    ipv4_lpm: Cached<Routes>,
}

impl Engine for L3Engine {
    #[inline]
    fn process(&mut self, f: &mut FrameCtx<'_>) -> Verdict {
        // parser
        let Some(eth) = Ethernet::parse(f.frame()) else {
            return Verdict::Drop;
        };
        if eth.ethertype != ETHERTYPE_IPV4 {
            return Verdict::Drop;
        }
        let Some(ip) = Ipv4::parse(f.frame(), ETH_HDR_LEN) else {
            return Verdict::Drop;
        };
        // control ingress
        if ip.ttl == 0 {
            return Verdict::Drop;
        }
        match *self.ipv4_lpm.get(&self.shared).apply(ip.dst) {
            Action::Forward { port, dmac } => {
                let frame = f.frame_mut();
                ip.set_ttl(frame, ip.ttl - 1);
                Ethernet::set_dst(frame, dmac);
                // deparser: the harness's only inner-packet touch (spec S1.5).
                zero_inner_checksums(frame);
                Verdict::Forward(port)
            }
            Action::Punt => Verdict::Punt,
            Action::Drop => Verdict::Drop,
        }
    }

    fn name(&self) -> &'static str {
        NAME
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::headers::{IP_PROTO_UDP, IPV4_MIN_HDR_LEN};

    fn key(text: &str) -> TypedKey {
        TypedKey::parse(SCHEMAS[0].key, text).expect("valid key")
    }

    fn mac(s: &str) -> TypedVal {
        TypedVal::parse(ValKind::Mac, s).expect("valid mac")
    }

    /// eth + ipv4(ttl, dst) + 8 payload bytes, with non-zero checksums.
    fn frame(dst: &str, ttl: u8) -> Vec<u8> {
        let mut f = vec![0u8; ETH_HDR_LEN + IPV4_MIN_HDR_LEN + 8];
        f[0..6].copy_from_slice(&[0xaa, 0, 0, 0, 0, 1]);
        f[6..12].copy_from_slice(&[0xaa, 0, 0, 0, 0, 2]);
        f[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        f[14] = 0x45;
        f[16..18].copy_from_slice(&28u16.to_be_bytes());
        f[22] = ttl;
        f[23] = IP_PROTO_UDP;
        f[24..26].copy_from_slice(&[0xde, 0xad]);
        f[26..30].copy_from_slice(&[10, 0, 0, 1]);
        f[30..34].copy_from_slice(&dst.parse::<std::net::Ipv4Addr>().expect("literal").octets());
        f[40..42].copy_from_slice(&[0xbe, 0xef]);
        f
    }

    fn run(engine: &mut dyn Engine, frame: &mut Vec<u8>) -> Verdict {
        let mut buf = vec![0u8; 64 + frame.len()];
        buf[64..].copy_from_slice(frame);
        let mut ctx = FrameCtx::new(&mut buf, 64, frame.len(), 0, 0).expect("fits");
        let v = engine.process(&mut ctx);
        frame.clear();
        frame.extend_from_slice(ctx.frame());
        v
    }

    fn routed() -> (L3Fwd, Box<dyn Engine>) {
        let p = L3Fwd::new(&PipelineParams::new([0, 1]));
        p.table_add(
            "ipv4_lpm",
            key("10.0.0.0/24"),
            "forward",
            &[TypedVal::U16(1), mac("bb:bb:bb:bb:bb:01")],
        )
        .expect("install");
        p.table_add(
            "ipv4_lpm",
            key("10.0.0.7/32"),
            "forward",
            &[TypedVal::U16(2), mac("bb:bb:bb:bb:bb:02")],
        )
        .expect("install");
        let e = p.engine();
        (p, e)
    }

    #[test]
    fn longest_prefix_wins() {
        let (_p, mut e) = routed();
        assert_eq!(
            run(&mut *e, &mut frame("10.0.0.9", 64)),
            Verdict::Forward(1)
        );
        assert_eq!(
            run(&mut *e, &mut frame("10.0.0.7", 64)),
            Verdict::Forward(2)
        );
    }

    #[test]
    fn a_miss_takes_the_default_action() {
        let (p, mut e) = routed();
        assert_eq!(run(&mut *e, &mut frame("192.168.1.1", 64)), Verdict::Drop);
        p.table_set_default("ipv4_lpm", "punt", &[])
            .expect("set default");
        assert_eq!(run(&mut *e, &mut frame("192.168.1.1", 64)), Verdict::Punt);
    }

    #[test]
    fn forwarding_decrements_ttl_rewrites_dmac_and_zeroes_checksums() {
        let (_p, mut e) = routed();
        let mut f = frame("10.0.0.9", 64);
        assert_eq!(run(&mut *e, &mut f), Verdict::Forward(1));
        assert_eq!(f[22], 63, "ttl decremented");
        assert_eq!(
            &f[0..6],
            &[0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0x01],
            "dmac rewritten"
        );
        assert_eq!(&f[6..12], &[0xaa, 0, 0, 0, 0, 2], "smac untouched");
        assert_eq!(&f[24..26], &[0, 0], "ipv4 checksum zero-filled");
        assert_eq!(&f[40..42], &[0, 0], "udp checksum zero-filled");
    }

    #[test]
    fn ttl_one_forwards_with_ttl_zero_and_ttl_zero_is_dropped() {
        let (_p, mut e) = routed();
        let mut f = frame("10.0.0.9", 1);
        assert_eq!(run(&mut *e, &mut f), Verdict::Forward(1));
        assert_eq!(f[22], 0);

        let mut f = frame("10.0.0.9", 0);
        let before = f.clone();
        assert_eq!(run(&mut *e, &mut f), Verdict::Drop);
        assert_eq!(f, before, "a dropped frame leaves the switch untouched");
    }

    #[test]
    fn non_ipv4_and_truncated_frames_are_dropped_by_the_parser() {
        let (_p, mut e) = routed();
        let mut arp = frame("10.0.0.9", 64);
        arp[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
        assert_eq!(run(&mut *e, &mut arp), Verdict::Drop);

        for len in [
            0,
            ETH_HDR_LEN - 1,
            ETH_HDR_LEN,
            ETH_HDR_LEN + IPV4_MIN_HDR_LEN - 1,
        ] {
            let mut short = frame("10.0.0.9", 64);
            short.truncate(len);
            assert_eq!(run(&mut *e, &mut short), Verdict::Drop, "len {len}");
        }
    }

    #[test]
    fn punt_action_reaches_the_harness_as_a_punt_verdict() {
        let (p, mut e) = routed();
        p.table_add("ipv4_lpm", key("10.9.0.0/16"), "punt", &[])
            .expect("install");
        assert_eq!(run(&mut *e, &mut frame("10.9.1.1", 64)), Verdict::Punt);
    }

    #[test]
    fn dump_is_longest_prefix_first_and_round_trips() {
        let (p, _e) = routed();
        p.table_add("ipv4_lpm", key("0.0.0.0/0"), "drop", &[])
            .expect("install");
        let dump = p.table_dump("ipv4_lpm").expect("known table");
        assert_eq!(
            dump.iter().map(|e| e.key.as_str()).collect::<Vec<_>>(),
            ["10.0.0.7/32", "10.0.0.0/24", "0.0.0.0/0"]
        );
        assert_eq!(dump[0].params["dmac"], "bb:bb:bb:bb:bb:02");
        assert_eq!(p.table_default("ipv4_lpm").expect("known table").key, "*");
        assert_eq!(p.table_clear("ipv4_lpm"), Ok(3));
        assert_eq!(p.table_dump("ipv4_lpm").expect("known table"), vec![]);
    }

    #[test]
    fn host_bits_in_a_route_are_canonicalized_not_duplicated() {
        let (p, _e) = routed();
        p.table_add("ipv4_lpm", key("10.0.0.55/24"), "drop", &[])
            .expect("install");
        let dump = p.table_dump("ipv4_lpm").expect("known table");
        assert_eq!(dump.iter().filter(|e| e.key == "10.0.0.0/24").count(), 1);
        assert_eq!(dump.len(), 2);
    }

    #[test]
    fn a_thousand_routes_resolve() {
        let p = L3Fwd::new(&PipelineParams::new([0, 1]));
        for i in 0..1000u32 {
            let addr = std::net::Ipv4Addr::from(0x0a00_0000 | (i << 8));
            p.table_add(
                "ipv4_lpm",
                key(&format!("{addr}/24")),
                "forward",
                &[TypedVal::U16((i % 2) as u16), mac("bb:bb:bb:bb:bb:01")],
            )
            .expect("install");
        }
        let mut e = p.engine();
        assert_eq!(
            run(&mut *e, &mut frame("10.3.231.5", 64)),
            Verdict::Forward(1),
            "route 999"
        );
        assert_eq!(run(&mut *e, &mut frame("11.0.0.1", 64)), Verdict::Drop);
    }
}
