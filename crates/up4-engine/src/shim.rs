//! The table shim (spec S7.3): the one interface between the control channel
//! and a pipeline's tables.
//!
//! The shim is *typed and self-describing*. A table publishes a static
//! [`TableSchema`] naming its key field, its match kind, and every action with
//! its parameters, so `up4ctl` can tell an operator what to type, reject a bad
//! entry before it reaches the datapath, and print a dump that reads like the
//! P4 source. Nothing here accepts an untyped byte string.

use crate::value::{TypedVal, ValKind, ValueError};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt};

/// How a table matches its key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "match_kind", content = "value_kind")]
pub enum KeyKind {
    /// P4 `exact`.
    Exact(ValKind),
    /// P4 `lpm`, written `value/prefix_len`.
    Lpm(ValKind),
}

impl KeyKind {
    /// The kind of the key's value.
    #[must_use]
    pub const fn value_kind(self) -> ValKind {
        match self {
            Self::Exact(k) | Self::Lpm(k) => k,
        }
    }

    /// How to spell a key of this kind, for help text.
    #[must_use]
    pub fn syntax(self) -> String {
        match self {
            Self::Exact(k) => k.syntax().to_owned(),
            Self::Lpm(k) => format!("{}/prefix_len", k.syntax()),
        }
    }
}

/// A table key, refined to the table's match kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TypedKey {
    /// An exact key.
    Exact(TypedVal),
    /// A prefix key.
    Lpm {
        /// The prefix's base value.
        value: TypedVal,
        /// Significant leading bits.
        prefix_len: u8,
    },
}

impl TypedKey {
    /// Parse `text` as a key of `kind`. The single text gate for keys.
    ///
    /// LPM keys accept a bare value as a host route (`/32` for IPv4), which is
    /// what an operator means when they type one.
    pub fn parse(kind: KeyKind, text: &str) -> Result<Self, ValueError> {
        match kind {
            KeyKind::Exact(vk) => Ok(Self::Exact(TypedVal::parse(vk, text)?)),
            KeyKind::Lpm(vk) => {
                let (value, len) = match text.split_once('/') {
                    None => (text, None),
                    Some((v, l)) => (
                        v,
                        Some(l.parse::<u8>().map_err(|_| ValueError::Malformed {
                            kind: vk,
                            text: text.to_owned(),
                        })?),
                    ),
                };
                let value = TypedVal::parse(vk, value)?;
                let width = match vk {
                    ValKind::U8 => 8,
                    ValKind::U16 => 16,
                    ValKind::U32 | ValKind::Ipv4 => 32,
                    ValKind::Mac => 48,
                };
                let prefix_len = len.unwrap_or(width);
                if prefix_len > width {
                    return Err(ValueError::Malformed {
                        kind: vk,
                        text: text.to_owned(),
                    });
                }
                Ok(Self::Lpm { value, prefix_len })
            }
        }
    }

    /// The key's value, whatever its match kind.
    #[must_use]
    pub const fn value(self) -> TypedVal {
        match self {
            Self::Exact(v) | Self::Lpm { value: v, .. } => v,
        }
    }

    /// The match kind this key was built for.
    #[must_use]
    pub const fn kind(self) -> KeyKind {
        match self {
            Self::Exact(v) => KeyKind::Exact(v.kind()),
            Self::Lpm { value, .. } => KeyKind::Lpm(value.kind()),
        }
    }
}

impl fmt::Display for TypedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exact(v) => write!(f, "{v}"),
            Self::Lpm { value, prefix_len } => write!(f, "{value}/{prefix_len}"),
        }
    }
}

/// One action parameter's name and kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParamSchema {
    /// Parameter name, as written in the P4 action signature.
    pub name: &'static str,
    /// Parameter kind.
    pub kind: ValKind,
}

/// One action's signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActionSchema {
    /// Action name, as written in the P4 source.
    pub name: &'static str,
    /// Parameters, in declaration order.
    pub params: &'static [ParamSchema],
}

/// A table's control-plane contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TableSchema {
    /// Table name, as written in the P4 source.
    pub name: &'static str,
    /// The key field's name, for help text and dumps.
    pub key_field: &'static str,
    /// How the key matches.
    pub key: KeyKind,
    /// Every action the table may run.
    pub actions: &'static [ActionSchema],
}

/// An owned rendering of a [`TableSchema`], for the control-plane wire.
///
/// The compiled contract is `&'static`; what travels over the socket is this.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaDesc {
    /// Table name.
    pub name: String,
    /// Key field name.
    pub key_field: String,
    /// Match kind and value kind.
    pub key: KeyKind,
    /// Actions, in declaration order.
    pub actions: Vec<ActionDesc>,
}

/// An owned rendering of an [`ActionSchema`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionDesc {
    /// Action name.
    pub name: String,
    /// Parameters, in declaration order.
    pub params: Vec<ParamDesc>,
}

/// An owned rendering of a [`ParamSchema`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParamDesc {
    /// Parameter name.
    pub name: String,
    /// Parameter kind.
    pub kind: ValKind,
}

impl TableSchema {
    /// Render this contract for the wire.
    #[must_use]
    pub fn describe(&self) -> SchemaDesc {
        SchemaDesc {
            name: self.name.to_owned(),
            key_field: self.key_field.to_owned(),
            key: self.key,
            actions: self
                .actions
                .iter()
                .map(|a| ActionDesc {
                    name: a.name.to_owned(),
                    params: a
                        .params
                        .iter()
                        .map(|p| ParamDesc {
                            name: p.name.to_owned(),
                            kind: p.kind,
                        })
                        .collect(),
                })
                .collect(),
        }
    }

    /// Look an action up by name.
    #[must_use]
    pub fn action(&self, name: &str) -> Option<&'static ActionSchema> {
        self.actions.iter().find(|a| a.name == name)
    }

    /// Refine `params` against `action`'s signature, checking arity and kinds.
    ///
    /// The gate every control-plane write passes through: an action reaches a
    /// pipeline only with the parameters its P4 signature declares.
    pub fn check(
        &self,
        action: &str,
        params: &[TypedVal],
    ) -> Result<&'static ActionSchema, TableError> {
        let schema = self
            .action(action)
            .ok_or_else(|| TableError::UnknownAction {
                table: self.name,
                action: action.to_owned(),
                known: self.actions.iter().map(|a| a.name.to_owned()).collect(),
            })?;
        if params.len() != schema.params.len() {
            return Err(TableError::Arity {
                table: self.name,
                action: schema.name,
                want: schema.params.len(),
                got: params.len(),
            });
        }
        for (given, want) in params.iter().zip(schema.params) {
            given.require(want.kind).map_err(TableError::Value)?;
        }
        Ok(schema)
    }
}

/// One installed entry, rendered for a dump.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryDesc {
    /// The key, in the syntax an operator would type.
    pub key: String,
    /// The action name.
    pub action: String,
    /// Action parameters by name.
    pub params: BTreeMap<String, String>,
}

/// Why a control-plane table operation was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TableError {
    /// The pipeline has no table by that name.
    UnknownTable {
        /// Name that was asked for.
        name: String,
        /// Names that exist.
        known: Vec<String>,
    },
    /// The table has no action by that name.
    UnknownAction {
        /// Table the action was sought in.
        table: &'static str,
        /// Name that was asked for.
        action: String,
        /// Names that exist.
        known: Vec<String>,
    },
    /// The key's match kind or value kind does not match the table's.
    KeyKindMismatch {
        /// Table whose contract was violated.
        table: &'static str,
        /// What the table declares.
        want: KeyKind,
        /// What was supplied.
        got: KeyKind,
    },
    /// Wrong number of action parameters.
    Arity {
        /// Table the action belongs to.
        table: &'static str,
        /// Action whose signature was violated.
        action: &'static str,
        /// Parameters the signature declares.
        want: usize,
        /// Parameters supplied.
        got: usize,
    },
    /// A parameter or key value was malformed or of the wrong kind.
    Value(ValueError),
    /// The entry to remove is not installed.
    NotFound {
        /// Table that was searched.
        table: &'static str,
        /// Key that was not found.
        key: String,
    },
    /// This pipeline has no tables at all (spec S8.2).
    NoTables {
        /// The pipeline that was addressed.
        pipeline: &'static str,
    },
}

impl fmt::Display for TableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownTable { name, known } => {
                write!(f, "no table {name:?} (have: {})", known.join(", "))
            }
            Self::UnknownAction {
                table,
                action,
                known,
            } => {
                write!(
                    f,
                    "table {table} has no action {action:?} (have: {})",
                    known.join(", ")
                )
            }
            Self::KeyKindMismatch { table, want, got } => {
                write!(
                    f,
                    "table {table} expects a {} key, got {}",
                    want.syntax(),
                    got.syntax()
                )
            }
            Self::Arity {
                table,
                action,
                want,
                got,
            } => {
                write!(f, "{table}.{action} takes {want} parameter(s), got {got}")
            }
            Self::Value(e) => write!(f, "{e}"),
            Self::NotFound { table, key } => write!(f, "table {table} has no entry {key}"),
            Self::NoTables { pipeline } => write!(f, "engine {pipeline} has no tables"),
        }
    }
}

impl std::error::Error for TableError {}

impl From<ValueError> for TableError {
    fn from(e: ValueError) -> Self {
        Self::Value(e)
    }
}

/// A pipeline's control-plane surface.
///
/// Implementations serialize writes through [`crate::table::Shared`], so an
/// operation is atomic with respect to packets in flight (spec S7.3): a frame
/// sees the table entirely before or entirely after each call. A *sequence* of
/// calls is not atomic.
pub trait TableOps: Send + Sync {
    /// Every table this pipeline exposes.
    fn schemas(&self) -> &'static [TableSchema];

    /// Install or replace an entry.
    fn table_add(
        &self,
        table: &str,
        key: TypedKey,
        action: &str,
        params: &[TypedVal],
    ) -> Result<(), TableError>;

    /// Remove an entry.
    fn table_remove(&self, table: &str, key: TypedKey) -> Result<(), TableError>;

    /// Every installed entry, in a deterministic order.
    fn table_dump(&self, table: &str) -> Result<Vec<EntryDesc>, TableError>;

    /// The action taken on a miss, described the same way an entry is. Its key
    /// renders as `*`, which is not a key an operator can install.
    fn table_default(&self, table: &str) -> Result<EntryDesc, TableError>;

    /// Replace the action taken on a miss (P4 `default_action`).
    fn table_set_default(
        &self,
        table: &str,
        action: &str,
        params: &[TypedVal],
    ) -> Result<(), TableError>;

    /// Remove every entry, returning how many were removed.
    fn table_clear(&self, table: &str) -> Result<usize, TableError>;

    /// The schema for `table`.
    fn schema(&self, table: &str) -> Result<&'static TableSchema, TableError> {
        self.schemas()
            .iter()
            .find(|s| s.name == table)
            .ok_or_else(|| TableError::UnknownTable {
                name: table.to_owned(),
                known: self.schemas().iter().map(|s| s.name.to_owned()).collect(),
            })
    }
}

/// The table surface of a pipeline that has none (spec S8.2: the control
/// channel answers "engine has no tables" rather than pretending to succeed).
#[derive(Clone, Copy, Debug)]
pub struct NoTables(pub &'static str);

impl TableOps for NoTables {
    fn schemas(&self) -> &'static [TableSchema] {
        &[]
    }

    fn table_add(&self, _: &str, _: TypedKey, _: &str, _: &[TypedVal]) -> Result<(), TableError> {
        Err(TableError::NoTables { pipeline: self.0 })
    }

    fn table_remove(&self, _: &str, _: TypedKey) -> Result<(), TableError> {
        Err(TableError::NoTables { pipeline: self.0 })
    }

    fn table_dump(&self, _: &str) -> Result<Vec<EntryDesc>, TableError> {
        Err(TableError::NoTables { pipeline: self.0 })
    }

    fn table_default(&self, _: &str) -> Result<EntryDesc, TableError> {
        Err(TableError::NoTables { pipeline: self.0 })
    }

    fn table_set_default(&self, _: &str, _: &str, _: &[TypedVal]) -> Result<(), TableError> {
        Err(TableError::NoTables { pipeline: self.0 })
    }

    fn table_clear(&self, _: &str) -> Result<usize, TableError> {
        Err(TableError::NoTables { pipeline: self.0 })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: TableSchema = TableSchema {
        name: "ipv4_lpm",
        key_field: "dst_addr",
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
                name: "drop",
                params: &[],
            },
        ],
    };

    #[test]
    fn lpm_keys_parse_with_and_without_a_prefix_length() {
        let with = TypedKey::parse(T.key, "10.0.0.0/24").expect("valid");
        assert_eq!(with.to_string(), "10.0.0.0/24");
        let bare = TypedKey::parse(T.key, "10.0.0.1").expect("valid");
        assert_eq!(
            bare.to_string(),
            "10.0.0.1/32",
            "a bare address is a host route"
        );
    }

    #[test]
    fn lpm_keys_reject_impossible_prefix_lengths_and_bad_values() {
        assert!(TypedKey::parse(T.key, "10.0.0.0/33").is_err());
        assert!(TypedKey::parse(T.key, "10.0.0.0/x").is_err());
        assert!(TypedKey::parse(T.key, "not-an-address/24").is_err());
    }

    #[test]
    fn exact_keys_carry_their_value_kind() {
        let k = TypedKey::parse(KeyKind::Exact(ValKind::Mac), "aa:bb:cc:dd:ee:01").expect("valid");
        assert_eq!(k.kind(), KeyKind::Exact(ValKind::Mac));
        assert_eq!(k.to_string(), "aa:bb:cc:dd:ee:01");
    }

    #[test]
    fn action_signatures_are_enforced() {
        let mac = TypedVal::parse(ValKind::Mac, "aa:bb:cc:dd:ee:01").expect("valid");
        assert!(T.check("forward", &[TypedVal::U16(1), mac]).is_ok());
        assert_eq!(
            T.check("forward", &[TypedVal::U16(1)]),
            Err(TableError::Arity {
                table: "ipv4_lpm",
                action: "forward",
                want: 2,
                got: 1
            })
        );
        assert_eq!(
            T.check("forward", &[mac, TypedVal::U16(1)]),
            Err(TableError::Value(ValueError::Mismatched {
                expected: ValKind::U16,
                got: ValKind::Mac
            }))
        );
        assert!(matches!(
            T.check("nope", &[]),
            Err(TableError::UnknownAction { .. })
        ));
    }

    #[test]
    fn a_pipeline_without_tables_says_so() {
        let n = NoTables("null");
        assert_eq!(
            n.table_dump("anything"),
            Err(TableError::NoTables { pipeline: "null" })
        );
        assert_eq!(n.schemas().len(), 0);
        assert!(n.schema("x").is_err());
    }
}
