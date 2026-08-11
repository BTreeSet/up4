//! The pipelines compiled into this binary.
//!
//! Each module is a rendering of the P4 program of the same name in
//! `p4/programs/`, structured to match it block for block: `parse`, then the
//! ingress control's table application, then the deparse-time fix-ups. Where
//! the P4 source and this code could drift, the P4 source wins (spec P1) and
//! the conformance corpus (spec S10) is what says so.

pub mod l2fwd;
pub mod l3fwd;
#[cfg(feature = "oracle")]
pub mod null;

use crate::{
    shim::{TableError, TableSchema, TypedKey},
    table::Ipv4Prefix,
    value::{MacAddr, TypedVal},
};

/// Extract an exact MAC key, or report the table's actual contract.
pub(crate) fn exact_mac(
    schema: &'static TableSchema,
    key: TypedKey,
) -> Result<MacAddr, TableError> {
    match key {
        TypedKey::Exact(TypedVal::Mac(m)) => Ok(m),
        other => Err(TableError::KeyKindMismatch {
            table: schema.name,
            want: schema.key,
            got: other.kind(),
        }),
    }
}

/// Extract an IPv4 LPM key, canonicalizing it into an [`Ipv4Prefix`].
pub(crate) fn lpm_ipv4(
    schema: &'static TableSchema,
    key: TypedKey,
) -> Result<Ipv4Prefix, TableError> {
    let mismatch = || TableError::KeyKindMismatch {
        table: schema.name,
        want: schema.key,
        got: key.kind(),
    };
    match key {
        TypedKey::Lpm {
            value: TypedVal::Ipv4(addr),
            prefix_len,
        } => Ipv4Prefix::new(addr, prefix_len).ok_or_else(mismatch),
        _ => Err(mismatch()),
    }
}

/// The `i`th action parameter as a `u16`.
///
/// [`TableSchema::check`] has already proved the arity and kinds; this repeats
/// the question only because the answer is what the caller needs, and it costs
/// nothing on the control plane.
pub(crate) fn param_u16(
    schema: &'static TableSchema,
    action: &'static str,
    params: &[TypedVal],
    i: usize,
) -> Result<u16, TableError> {
    params
        .get(i)
        .copied()
        .and_then(TypedVal::as_u16)
        .ok_or(TableError::Arity {
            table: schema.name,
            action,
            want: i + 1,
            got: params.len(),
        })
}

/// The `i`th action parameter as a MAC address.
pub(crate) fn param_mac(
    schema: &'static TableSchema,
    action: &'static str,
    params: &[TypedVal],
    i: usize,
) -> Result<MacAddr, TableError> {
    params
        .get(i)
        .copied()
        .and_then(TypedVal::as_mac)
        .ok_or(TableError::Arity {
            table: schema.name,
            action,
            want: i + 1,
            got: params.len(),
        })
}
