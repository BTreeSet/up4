//! Configuration violations, and the accumulator that collects all of them.

use std::fmt;

/// One configuration violation.
///
/// Closed sum: every rule in spec S5 has exactly one variant, and each variant
/// carries what the operator needs to fix it.
// Every variant's fields are named for exactly what they carry (the offending
// value, and the context needed to locate it); per-field prose would be filler.
#[allow(missing_docs)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfigError {
    /// The file is not valid TOML, or has an unknown/misspelled field.
    Toml(String),
    /// `node.bind` did not parse as `addr:port`.
    Bind { value: String },
    /// `node.fabric` was not `ipv4` or `ipv6`.
    Fabric { value: String },
    /// `node.threads` outside `1..=16`.
    Threads { value: u32 },
    /// `node.pipeline` is not compiled into this binary.
    UnknownPipeline { value: String, known: Vec<String> },
    /// `node.id` was empty.
    EmptyNodeId,
    /// `node.ctl_socket` was empty.
    EmptyCtlSocket,
    /// `node.pin_cores` was given but does not have one core per shard.
    PinCoresArity { given: usize, threads: usize },
    /// A core id in `node.pin_cores` was negative.
    NegativeCore { value: i64 },
    /// No `[[vport]]` was declared: a switch with no ports cannot forward.
    NoVports,
    /// A vport id does not fit in `u16` or is the reserved punt id.
    VportId { value: i64 },
    /// Two `[[vport]]` entries share an id.
    DuplicateVportId { value: u16 },
    /// A `[[vport]]` peer did not parse as `addr:port`.
    Peer { vport: i64, value: String },
    /// Two vports share a peer tuple, which is the receive demux key (S5).
    DuplicatePeer {
        value: String,
        first: u16,
        second: u16,
    },
    /// A vport's peer is this node's own bind address.
    PeerIsSelf { vport: u16, value: String },
    /// `[punt] vport` was not the reserved id.
    PuntVport { value: i64, reserved: u16 },
    /// A validation defect: reported rather than panicked so a bug here cannot
    /// take the process down with a backtrace. Never observed in practice.
    Internal(&'static str),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Toml(e) => write!(f, "{e}"),
            Self::Bind { value } => write!(f, "node.bind {value:?} is not a valid addr:port"),
            Self::Fabric { value } => {
                write!(f, "node.fabric {value:?} is not \"ipv4\" or \"ipv6\"")
            }
            Self::Threads { value } => {
                write!(
                    f,
                    "node.threads {value} is outside 1..={}",
                    crate::Threads::MAX
                )
            }
            Self::UnknownPipeline { value, known } => write!(
                f,
                "node.pipeline {value:?} is not compiled into this binary (have: {})",
                known.join(", ")
            ),
            Self::EmptyNodeId => write!(f, "node.id must not be empty"),
            Self::EmptyCtlSocket => write!(f, "node.ctl_socket must not be empty"),
            Self::PinCoresArity { given, threads } => write!(
                f,
                "node.pin_cores has {given} entries but node.threads is {threads}; \
                 give one core per shard or omit pin_cores entirely"
            ),
            Self::NegativeCore { value } => write!(f, "node.pin_cores entry {value} is negative"),
            Self::NoVports => write!(f, "at least one [[vport]] is required"),
            Self::VportId { value } => write!(
                f,
                "vport id {value} is not in 0..{punt} ({punt} is the reserved punt id)",
                punt = up4_wire::PUNT_VPORT
            ),
            Self::DuplicateVportId { value } => write!(f, "vport id {value} is declared twice"),
            Self::Peer { vport, value } => {
                write!(f, "vport {vport} peer {value:?} is not a valid addr:port")
            }
            Self::DuplicatePeer {
                value,
                first,
                second,
            } => write!(
                f,
                "vports {first} and {second} share peer {value}; the peer tuple is the \
                 receive demux key and must be unique"
            ),
            Self::PeerIsSelf { vport, value } => {
                write!(
                    f,
                    "vport {vport} peer {value} is this node's own bind address"
                )
            }
            Self::PuntVport { value, reserved } => {
                write!(f, "[punt] vport {value} must be the reserved id {reserved}")
            }
            Self::Internal(what) => write!(f, "internal validation defect: {what}"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// A non-empty list of violations.
///
/// Non-emptiness is structural: the only ways to build one are
/// [`ConfigErrors::single`] and `Errors::into_result`, and the latter yields
/// `Ok` when nothing was collected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigErrors {
    first: ConfigError,
    rest: Vec<ConfigError>,
}

impl ConfigErrors {
    /// One violation.
    #[must_use]
    pub fn single(e: ConfigError) -> Self {
        Self {
            first: e,
            rest: Vec::new(),
        }
    }

    /// All violations, in discovery order.
    pub fn iter(&self) -> impl Iterator<Item = &ConfigError> {
        std::iter::once(&self.first).chain(&self.rest)
    }

    /// How many violations were found.
    #[must_use]
    pub fn len(&self) -> usize {
        1 + self.rest.len()
    }

    /// Always false; present because clippy asks for it next to `len`.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }
}

impl fmt::Display for ConfigErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{} configuration error(s):", self.len())?;
        for e in self.iter() {
            writeln!(f, "  - {e}")?;
        }
        Ok(())
    }
}

impl std::error::Error for ConfigErrors {}

/// Accumulator used during validation: collect everything, decide once.
#[derive(Default)]
pub(crate) struct Errors(Vec<ConfigError>);

impl Errors {
    pub(crate) fn push(&mut self, e: ConfigError) {
        self.0.push(e);
    }

    /// How many violations have been collected so far.
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    /// Record `e` if `value` is absent, and pass the value through.
    pub(crate) fn require<T>(
        &mut self,
        value: Option<T>,
        e: impl FnOnce() -> ConfigError,
    ) -> Option<T> {
        if value.is_none() {
            self.push(e());
        }
        value
    }

    /// Decide once: the built value if nothing was collected, every violation
    /// otherwise.
    ///
    /// `built` is `None` exactly when some refinement failed, and every failed
    /// refinement pushed an error — so the third arm is unreachable, and says
    /// so in a value rather than a panic.
    pub(crate) fn into_result<T>(self, built: Option<T>) -> Result<T, ConfigErrors> {
        let mut it = self.0.into_iter();
        match (built, it.next()) {
            (Some(v), None) => Ok(v),
            (_, Some(first)) => Err(ConfigErrors {
                first,
                rest: it.collect(),
            }),
            (None, None) => Err(ConfigErrors::single(ConfigError::Internal(
                "refinement failed without recording a violation",
            ))),
        }
    }
}
