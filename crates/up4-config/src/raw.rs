//! The serde mirror of `up4.toml`, and the single transition from it to the
//! domain model.
//!
//! Nothing outside this module ever sees a `Raw*` value. Fields are typed as
//! wide as the file allows (`String`, `i64`) precisely so that an out-of-range
//! value reaches [`RawConfig::validate`] as data to report, instead of
//! aborting deserialization at the first mistake and hiding the rest.

use crate::{
    Config, Fabric, NodeConfig, PuntConfig, Threads, VportId,
    error::{ConfigError, ConfigErrors, Errors},
    vport::{Vport, VportTable},
};
use serde::Deserialize;
use std::{net::SocketAddr, path::PathBuf, time::Duration};
use up4_wire::PUNT_VPORT;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawConfig {
    node: RawNode,
    #[serde(default)]
    vport: Vec<RawVport>,
    punt: Option<RawPunt>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawNode {
    id: String,
    bind: String,
    #[serde(default = "default_fabric")]
    fabric: String,
    pipeline: String,
    #[serde(default = "default_threads")]
    threads: u32,
    pin_cores: Option<Vec<i64>>,
    ctl_socket: String,
    #[serde(default = "default_metrics_interval_s")]
    metrics_interval_s: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawVport {
    id: i64,
    peer: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPunt {
    vport: i64,
}

fn default_fabric() -> String {
    Fabric::default().as_str().to_owned()
}

const fn default_threads() -> u32 {
    1
}

const fn default_metrics_interval_s() -> u64 {
    5
}

impl RawConfig {
    /// Refine every field, recording every violation.
    ///
    /// Cost: O(v) in vports plus the index construction in
    /// [`VportTable::build`].
    pub(crate) fn validate(self, registry: &[&str]) -> Result<Config, ConfigErrors> {
        let mut errs = Errors::default();
        let n = self.node;

        let bind = errs.require(n.bind.parse::<SocketAddr>().ok(), || ConfigError::Bind {
            value: n.bind.clone(),
        });
        let fabric = errs.require(Fabric::from_config_str(&n.fabric), || ConfigError::Fabric {
            value: n.fabric.clone(),
        });
        let threads = errs.require(u8::try_from(n.threads).ok().and_then(Threads::new), || {
            ConfigError::Threads { value: n.threads }
        });
        if n.id.is_empty() {
            errs.push(ConfigError::EmptyNodeId);
        }
        if n.ctl_socket.is_empty() {
            errs.push(ConfigError::EmptyCtlSocket);
        }
        if !registry.contains(&n.pipeline.as_str()) {
            errs.push(ConfigError::UnknownPipeline {
                value: n.pipeline.clone(),
                known: registry.iter().map(|s| (*s).to_owned()).collect(),
            });
        }

        let pin_cores = match n.pin_cores {
            None => Vec::new(),
            Some(raw) => {
                if let Some(t) = threads
                    && raw.len() != t.get()
                {
                    errs.push(ConfigError::PinCoresArity {
                        given: raw.len(),
                        threads: t.get(),
                    });
                }
                raw.iter()
                    .filter_map(|c| {
                        usize::try_from(*c)
                            .map_err(|_| errs.push(ConfigError::NegativeCore { value: *c }))
                            .ok()
                    })
                    .collect()
            }
        };

        if self.vport.is_empty() {
            errs.push(ConfigError::NoVports);
        }
        let vports: Vec<Vport> = self
            .vport
            .iter()
            .filter_map(|v| {
                let id = errs.require(u16::try_from(v.id).ok().and_then(VportId::new), || {
                    ConfigError::VportId { value: v.id }
                });
                let peer = errs.require(v.peer.parse::<SocketAddr>().ok(), || ConfigError::Peer {
                    vport: v.id,
                    value: v.peer.clone(),
                });
                let (id, peer) = (id?, peer?);
                if bind == Some(peer) {
                    errs.push(ConfigError::PeerIsSelf {
                        vport: id.get(),
                        value: v.peer.clone(),
                    });
                }
                Some(Vport { id, peer })
            })
            .collect();
        // Only build the table when every entry refined: a table missing the
        // entries that failed would report spurious "unique" success.
        let table = (vports.len() == self.vport.len() && !vports.is_empty())
            .then(|| VportTable::build(vports, &mut errs))
            .flatten();

        let punt = self.punt.map(|p| {
            if p.vport != i64::from(PUNT_VPORT) {
                errs.push(ConfigError::PuntVport {
                    value: p.vport,
                    reserved: PUNT_VPORT,
                });
            }
            PuntConfig { vport: PUNT_VPORT }
        });

        let built = (|| {
            Some(Config {
                node: NodeConfig {
                    id: n.id,
                    bind: bind?,
                    fabric: fabric?,
                    pipeline: n.pipeline,
                    threads: threads?,
                    pin_cores: pin_cores.into_boxed_slice(),
                    ctl_socket: PathBuf::from(n.ctl_socket),
                    metrics_interval: (n.metrics_interval_s > 0)
                        .then(|| Duration::from_secs(n.metrics_interval_s)),
                },
                vports: table?,
                punt,
            })
        })();
        errs.into_result(built)
    }
}
