//! up4 configuration (spec S5).
//!
//! This crate is the second of the two gates through which untrusted bytes
//! enter up4 (the first is [`up4_wire::decode`]). It follows *parse, don't
//! validate*: [`Config::from_toml`] is the only constructor, it collects
//! **every** violation rather than the first (spec S5), and what it returns is
//! a value in which the violations it checks for are unrepresentable;
//! [`VportId`] cannot hold the reserved punt id, [`Threads`] cannot hold 0 or
//! 17, [`VportTable`] cannot hold a duplicate id or a duplicate peer tuple.
//!
//! Downstream code therefore has no configuration error handling in it at all.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod error;
mod raw;
mod vport;

pub use error::{ConfigError, ConfigErrors};
pub use vport::{Vport, VportIdx, VportTable};

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};
use up4_wire::PUNT_VPORT;

/// Which address family the fabric (outer) packets use.
///
/// The variant selects the inner MTU, so no code downstream branches on a
/// string or recomputes 1500 - headers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Fabric {
    /// IPv4 fabric: 20 B IP + 8 B UDP + 12 B overlay under a 1500 B path MTU.
    #[default]
    V4,
    /// IPv6 fabric: 40 B IP + 8 B UDP + 12 B overlay under a 1500 B path MTU.
    V6,
}

impl Fabric {
    /// Largest inner Ethernet frame this fabric can carry (spec S4).
    #[must_use]
    pub const fn inner_mtu(self) -> usize {
        match self {
            Self::V4 => up4_wire::INNER_MTU_V4,
            Self::V6 => up4_wire::INNER_MTU_V6,
        }
    }

    /// Parse the config spelling of a fabric. The single gate: `Fabric` has
    /// no other constructor, so no "unknown fabric" state exists downstream.
    #[must_use]
    pub fn from_config_str(s: &str) -> Option<Self> {
        match s {
            "ipv4" => Some(Self::V4),
            "ipv6" => Some(Self::V6),
            _ => None,
        }
    }

    /// Config spelling of this fabric.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V4 => "ipv4",
            Self::V6 => "ipv6",
        }
    }
}

/// A vport identifier: any u16 except the reserved punt id.
///
/// Private field, one smart constructor: a `VportId` in hand is proof that the
/// id is legal, so nothing downstream re-checks it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VportId(u16);

impl VportId {
    /// Refine a raw id, rejecting the reserved punt id (spec S5).
    #[must_use]
    pub const fn new(raw: u16) -> Option<Self> {
        if raw == PUNT_VPORT {
            None
        } else {
            Some(Self(raw))
        }
    }

    /// The raw id, for the wire and for engine verdicts.
    #[inline]
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

impl std::fmt::Display for VportId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A shard count in `1..=16` (spec S5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Threads(u8);

impl Threads {
    /// Smallest legal shard count.
    pub const MIN: u8 = 1;
    /// Largest legal shard count.
    pub const MAX: u8 = 16;

    /// Refine a raw count.
    #[must_use]
    pub const fn new(raw: u8) -> Option<Self> {
        if raw >= Self::MIN && raw <= Self::MAX {
            Some(Self(raw))
        } else {
            None
        }
    }

    /// The count as a `usize`, for sizing per-shard structures.
    #[inline]
    #[must_use]
    pub const fn get(self) -> usize {
        self.0 as usize
    }
}

impl Default for Threads {
    fn default() -> Self {
        Self(1)
    }
}

/// Node-scoped settings.
#[derive(Clone, Debug)]
pub struct NodeConfig {
    /// Log label only; carries no semantics.
    pub id: String,
    /// Address the fabric socket(s) bind to.
    pub bind: SocketAddr,
    /// Outer address family.
    pub fabric: Fabric,
    /// Name of a pipeline in the compiled-in registry (spec S7).
    pub pipeline: String,
    /// Number of rx/tx shard pairs.
    pub threads: Threads,
    /// Core ids to pin shards to, in shard order; empty means "do not pin".
    pub pin_cores: Box<[usize]>,
    /// Path of the control channel's `SOCK_SEQPACKET` socket.
    pub ctl_socket: PathBuf,
    /// Counter snapshot period; `None` when `metrics_interval_s = 0`.
    pub metrics_interval: Option<Duration>,
}

/// Punt configuration (spec S5, S8.3).
///
/// The struct is a witness that punting is enabled; when it is absent, punt
/// verdicts count `punt_unconfigured_drop` and there is no queue to speak of.
#[derive(Clone, Copy, Debug)]
pub struct PuntConfig {
    /// Always [`up4_wire::PUNT_VPORT`]; kept as a field so the config file's
    /// value is echoed back rather than silently ignored.
    pub vport: u16,
}

/// A validated up4 configuration.
#[derive(Clone, Debug)]
pub struct Config {
    /// Node-scoped settings.
    pub node: NodeConfig,
    /// The vports, with their id and peer indexes prebuilt.
    pub vports: VportTable,
    /// Punt channel, if enabled.
    pub punt: Option<PuntConfig>,
}

impl Config {
    /// Parse and validate a configuration.
    ///
    /// `registry` is the list of pipeline names compiled into this binary,
    /// passed in so this crate stays engine-agnostic (spec S5 / M1 seam).
    ///
    /// Every violation found is reported, not just the first. The one
    /// exception is a TOML syntax error, which leaves nothing further to check.
    ///
    /// Cost: O(v) in the number of vports, plus building the O(1)-lookup
    /// indexes in [`VportTable`].
    pub fn from_toml(src: &str, registry: &[&str]) -> Result<Self, ConfigErrors> {
        let raw: raw::RawConfig = toml::from_str(src)
            .map_err(|e| ConfigErrors::single(ConfigError::Toml(e.to_string())))?;
        raw.validate(registry)
    }

    /// Read and validate a configuration file.
    pub fn load(path: &Path, registry: &[&str]) -> Result<Self, LoadError> {
        let src = std::fs::read_to_string(path).map_err(|source| LoadError::Io {
            path: path.to_owned(),
            source,
        })?;
        Self::from_toml(&src, registry).map_err(LoadError::Invalid)
    }

    /// Largest inner frame this node may transmit.
    #[must_use]
    pub fn inner_mtu(&self) -> usize {
        self.node.fabric.inner_mtu()
    }
}

/// Why a configuration file could not be turned into a [`Config`].
#[derive(Debug)]
pub enum LoadError {
    /// The file could not be read.
    Io {
        /// Path that was attempted.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// The file was read but is not a valid configuration.
    Invalid(ConfigErrors),
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "cannot read {}: {source}", path.display()),
            Self::Invalid(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for LoadError {}

#[cfg(test)]
mod tests;
