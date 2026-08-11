//! The control-channel protocol (spec S8.2).
//!
//! Requests and responses are closed sums, so the server's dispatch is one
//! exhaustive `match` and adding a command is a compile error until every side
//! handles it. Values cross the wire as the text an operator types: the server
//! refines them against the pipeline's table schema, which is the single place
//! control-plane text becomes typed (spec S7.3).

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use up4_engine::{EntryDesc, SchemaDesc};
use up4_metrics::Snapshot;

/// Action parameters, as written by hand or by a script.
///
/// Both spellings mean the same thing; named form is order-free and is what
/// `up4ctl` sends when every argument looks like `name=value`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Params {
    /// Positional, in the action's declaration order.
    Positional(Vec<String>),
    /// Named, matching the action's parameter names.
    Named(BTreeMap<String, String>),
}

impl Default for Params {
    fn default() -> Self {
        Self::Positional(Vec::new())
    }
}

impl Params {
    /// Interpret command-line arguments: all `name=value` means named form.
    #[must_use]
    pub fn from_args(args: &[String]) -> Self {
        if !args.is_empty() && args.iter().all(|a| a.contains('=')) {
            Self::Named(
                args.iter()
                    .filter_map(|a| a.split_once('=').map(|(k, v)| (k.to_owned(), v.to_owned())))
                    .collect(),
            )
        } else {
            Self::Positional(args.to_vec())
        }
    }

    /// How many parameters were given.
    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            Self::Positional(v) => v.len(),
            Self::Named(m) => m.len(),
        }
    }

    /// Whether none were given.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// One table entry, as a batch file or a single command spells it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntrySpec {
    /// Table name.
    pub table: String,
    /// Key, in the table's key syntax (`10.0.0.0/24`, `aa:bb:cc:dd:ee:01`).
    pub key: String,
    /// Action name.
    pub action: String,
    /// Action parameters.
    #[serde(default)]
    pub params: Params,
}

/// A batch of entries, as `up4ctl table load` and `up4d --tables` read them.
///
/// Accepts either `{"entries": [...]}` or a bare `[...]`, because both are what
/// people write.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EntryBatch {
    /// `{"entries": [...]}`
    Wrapped {
        /// The entries.
        entries: Vec<EntrySpec>,
    },
    /// `[...]`
    Bare(Vec<EntrySpec>),
}

impl EntryBatch {
    /// The entries, however they were spelled.
    #[must_use]
    pub fn into_entries(self) -> Vec<EntrySpec> {
        match self {
            Self::Wrapped { entries } | Self::Bare(entries) => entries,
        }
    }
}

/// A command (spec S8.2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "kebab-case")]
pub enum Request {
    /// Liveness.
    Ping,
    /// Build info, pipeline, topology, probe results.
    Info,
    /// Counter snapshot.
    Counters,
    /// Every table's schema: what to type, straight from the P4 source.
    Tables,
    /// Install or replace entries.
    TableAdd {
        /// The entries to install.
        entries: Vec<EntrySpec>,
    },
    /// Remove one entry.
    TableDel {
        /// Table name.
        table: String,
        /// Key to remove.
        key: String,
    },
    /// Every installed entry, plus the default action.
    TableDump {
        /// Table name.
        table: String,
    },
    /// Replace the action taken on a miss.
    TableSetDefault {
        /// Table name.
        table: String,
        /// Action name.
        action: String,
        /// Action parameters.
        #[serde(default)]
        params: Params,
    },
    /// Remove every entry.
    TableClear {
        /// Table name.
        table: String,
    },
    /// Take up to `max` punted frames.
    PuntDrain {
        /// Maximum frames to return.
        max: usize,
    },
    /// Stop rx, flush tx, write a final snapshot, exit 0.
    Shutdown,
}

/// One punted frame on the wire (spec S8.3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PuntedFrame {
    /// Vport the frame arrived on.
    pub ingress_vport: u16,
    /// Harness receive timestamp.
    pub rx_ts_us: u32,
    /// The inner Ethernet frame, base64.
    pub frame_b64: String,
}

/// What the node knows about itself.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Info {
    /// `node.id`.
    pub node: String,
    /// up4 version.
    pub version: String,
    /// Loaded pipeline name.
    pub pipeline: String,
    /// One line about that pipeline.
    pub pipeline_summary: String,
    /// Seconds since startup.
    pub uptime_s: u64,
    /// Shard count.
    pub threads: usize,
    /// Fabric family.
    pub fabric: String,
    /// Largest inner frame.
    pub inner_mtu: usize,
    /// Address the shards are bound to.
    pub bind: String,
    /// Whether `[punt]` is configured.
    pub punt_enabled: bool,
    /// The topology.
    pub vports: Vec<VportInfo>,
    /// Startup probe (spec S11.1), verbatim.
    pub probe: serde_json::Value,
}

/// One vport, for `info`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VportInfo {
    /// Configured id.
    pub id: u16,
    /// Peer tuple.
    pub peer: String,
}

/// A reply (spec S8.2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum Response {
    /// Answer to `ping`.
    Pong,
    /// Answer to `info`.
    Info(Box<Info>),
    /// Answer to `counters`.
    Counters(Box<Snapshot>),
    /// Answer to `tables`.
    ///
    /// A struct variant, not a newtype one: serde's internally tagged
    /// representation cannot serialize a newtype variant wrapping a sequence,
    /// and that failure would only appear over a socket.
    Tables {
        /// One schema per table the pipeline exposes.
        tables: Vec<SchemaDesc>,
    },
    /// Answer to `table-dump`.
    Entries {
        /// Installed entries, in the table's natural order.
        entries: Vec<EntryDesc>,
        /// The action taken on a miss.
        default: EntryDesc,
    },
    /// Answer to a write: how many entries it affected.
    Applied {
        /// Entries added, removed, or cleared.
        count: usize,
    },
    /// Answer to `punt-drain`.
    Punted {
        /// The frames, oldest first.
        frames: Vec<PuntedFrame>,
        /// Frames still queued.
        remaining: usize,
    },
    /// Answer to `shutdown`, sent before the node stops.
    ShuttingDown,
    /// The command was refused. The message is the operator-facing reason.
    Error {
        /// Why.
        message: String,
    },
}

impl Response {
    /// A refusal carrying `e`'s message.
    pub fn error(e: impl std::fmt::Display) -> Self {
        Self::Error {
            message: e.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every reply must survive the socket, including the shapes serde's
    /// internally tagged representation refuses.
    #[test]
    fn every_response_shape_round_trips_through_json() {
        use up4_engine::{EntryDesc, KeyKind, SchemaDesc, ValKind};
        let entry = EntryDesc {
            key: "10.0.0.0/24".into(),
            action: "forward".into(),
            params: BTreeMap::from([("port".to_owned(), "1".to_owned())]),
        };
        let responses = [
            Response::Pong,
            Response::ShuttingDown,
            Response::Applied { count: 3 },
            Response::Error {
                message: "no".into(),
            },
            Response::Tables {
                tables: vec![SchemaDesc {
                    name: "ipv4_lpm".into(),
                    key_field: "ipv4.dst".into(),
                    key: KeyKind::Lpm(ValKind::Ipv4),
                    actions: Vec::new(),
                }],
            },
            Response::Entries {
                entries: vec![entry.clone()],
                default: entry,
            },
            Response::Punted {
                frames: vec![PuntedFrame {
                    ingress_vport: 1,
                    rx_ts_us: 2,
                    frame_b64: "AAA=".into(),
                }],
                remaining: 0,
            },
        ];
        for response in responses {
            let text = serde_json::to_string(&response)
                .unwrap_or_else(|e| panic!("{response:?} does not serialize: {e}"));
            assert_eq!(
                serde_json::from_str::<Response>(&text).expect("parses"),
                response
            );
        }
    }

    #[test]
    fn requests_round_trip_through_json() {
        let reqs = [
            Request::Ping,
            Request::Counters,
            Request::TableDel {
                table: "t".into(),
                key: "10.0.0.0/24".into(),
            },
            Request::TableAdd {
                entries: vec![EntrySpec {
                    table: "ipv4_lpm".into(),
                    key: "10.0.0.0/24".into(),
                    action: "forward".into(),
                    params: Params::from_args(&["port=1".into(), "dmac=aa:bb:cc:dd:ee:01".into()]),
                }],
            },
        ];
        for req in reqs {
            let text = serde_json::to_string(&req).expect("serializes");
            assert_eq!(serde_json::from_str::<Request>(&text).expect("parses"), req);
        }
    }

    #[test]
    fn params_take_the_shape_the_operator_used() {
        assert_eq!(
            Params::from_args(&["port=1".into()]),
            Params::Named(BTreeMap::from([("port".into(), "1".into())]))
        );
        assert_eq!(
            Params::from_args(&["1".into(), "aa:bb:cc:dd:ee:01".into()]),
            Params::Positional(vec!["1".into(), "aa:bb:cc:dd:ee:01".into()])
        );
        assert!(Params::from_args(&[]).is_empty());
    }

    #[test]
    fn batches_accept_both_spellings() {
        let entry = r#"{"table":"t","key":"k","action":"a"}"#;
        let wrapped: EntryBatch =
            serde_json::from_str(&format!(r#"{{"entries":[{entry}]}}"#)).expect("wrapped form");
        let bare: EntryBatch = serde_json::from_str(&format!("[{entry}]")).expect("bare form");
        assert_eq!(wrapped.into_entries(), bare.into_entries());
    }

    #[test]
    fn a_missing_params_field_means_no_parameters() {
        let spec: EntrySpec =
            serde_json::from_str(r#"{"table":"t","key":"k","action":"drop"}"#).expect("parses");
        assert!(spec.params.is_empty());
    }
}
