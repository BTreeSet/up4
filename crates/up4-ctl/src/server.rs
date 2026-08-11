//! The control server (spec S8).
//!
//! One thread, one connection at a time, `SOCK_SEQPACKET` at mode 0600 — the
//! filesystem is the authorization boundary (spec S8.1). Command handling is
//! [`handle`], a plain function over a [`Context`], so every command is
//! testable without a socket in sight; the socket code below it does nothing
//! but frame bytes and hand them over.

use crate::{
    b64,
    codec::{self},
    protocol::{EntrySpec, Info, Params, PuntedFrame, Request, Response},
};
use socket2::{Domain, SockAddr, Socket, Type};
use std::{
    io,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tracing::{debug, info, warn};
use up4_engine::{
    ActionSchema, Pipeline, TableError, TableOps, TableSchema, TypedKey, TypedVal, ValueError,
};
use up4_io::{PuntQueue, Stop, clock};
use up4_metrics::Metrics;

/// How long `accept` blocks before the loop re-checks the stop flag.
const ACCEPT_TIMEOUT: Duration = Duration::from_millis(200);

/// Most frames one `punt-drain` returns, so a reply always fits a control
/// frame ([`codec::MAX_FRAME`]).
pub const PUNT_DRAIN_MAX: usize = 64;

/// How long a connected client may say nothing before the server hangs up.
///
/// Connections are served one at a time, so an idle one is not merely
/// impolite — it holds the whole control channel. Bound it (AGENTS.md rule 8).
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Everything the control channel is allowed to touch.
pub struct Context {
    /// Static half of the `info` reply; uptime is filled in per call.
    pub info: Info,
    /// Monotonic microseconds at startup, for uptime.
    pub started_us: u64,
    /// The counter registry.
    pub metrics: Arc<Metrics>,
    /// The loaded pipeline, for table operations.
    pub pipeline: Arc<dyn Pipeline>,
    /// The punt queue, when `[punt]` is configured.
    pub punt: Option<Arc<PuntQueue>>,
    /// The process-wide stop flag, which `shutdown` sets.
    pub stop: Stop,
}

/// Execute one command.
///
/// Total: every request has exactly one reply, and every refusal carries the
/// reason an operator needs. Table writes are serialized by the pipeline's own
/// publication discipline (spec S7.3), so this needs no lock of its own.
pub fn handle(ctx: &Context, request: Request) -> Response {
    let tables = ctx.pipeline.tables();
    match request {
        Request::Ping => Response::Pong,
        Request::Info => {
            let mut info = ctx.info.clone();
            info.uptime_s = (clock::monotonic_us().saturating_sub(ctx.started_us)) / 1_000_000;
            Response::Info(Box::new(info))
        }
        Request::Counters => Response::Counters(Box::new(ctx.metrics.snapshot(clock::wall_us()))),
        Request::Tables => Response::Tables {
            tables: tables.schemas().iter().map(TableSchema::describe).collect(),
        },
        Request::TableDump { table } => {
            match (tables.table_dump(&table), tables.table_default(&table)) {
                (Ok(entries), Ok(default)) => Response::Entries { entries, default },
                (Err(e), _) | (_, Err(e)) => Response::error(e),
            }
        }
        Request::TableAdd { entries } => match apply_entries(tables, &entries) {
            Ok(count) => Response::Applied { count },
            Err(message) => Response::Error { message },
        },
        Request::TableDel { table, key } => match parse_key(tables.schema(&table), &key) {
            Err(e) => Response::error(e),
            Ok((schema, key)) => match tables.table_remove(schema.name, key) {
                Ok(()) => Response::Applied { count: 1 },
                Err(e) => Response::error(e),
            },
        },
        Request::TableSetDefault {
            table,
            action,
            params,
        } => {
            match tables
                .schema(&table)
                .and_then(|s| Ok((s, typed_params(s, &action, &params)?)))
            {
                Err(e) => Response::error(e),
                Ok((schema, params)) => {
                    match tables.table_set_default(schema.name, &action, &params) {
                        Ok(()) => Response::Applied { count: 1 },
                        Err(e) => Response::error(e),
                    }
                }
            }
        }
        Request::TableClear { table } => match tables.table_clear(&table) {
            Ok(count) => Response::Applied { count },
            Err(e) => Response::error(e),
        },
        Request::PuntDrain { max } => match &ctx.punt {
            None => Response::error("punt is not configured on this node ([punt] in up4.toml)"),
            Some(queue) => {
                let frames = queue
                    .drain(max.min(PUNT_DRAIN_MAX))
                    .into_iter()
                    .map(|f| PuntedFrame {
                        ingress_vport: f.ingress_vport,
                        rx_ts_us: f.rx_ts_us,
                        frame_b64: b64::encode(&f.bytes),
                    })
                    .collect();
                Response::Punted {
                    frames,
                    remaining: queue.len(),
                }
            }
        },
        Request::Shutdown => {
            info!("shutdown requested over the control channel");
            ctx.stop.request();
            Response::ShuttingDown
        }
    }
}

/// Install a batch of entries, stopping at the first refusal.
///
/// Partial application is the documented consistency model (spec S7.3: atomic
/// per entry, not per batch), so the error says how many took effect.
///
/// This is the single implementation of "install these entries": the control
/// command and `up4d --tables` both come through here, so the file format and
/// every refusal message are the same on both paths.
pub fn apply_entries(tables: &dyn TableOps, entries: &[EntrySpec]) -> Result<usize, String> {
    for (i, spec) in entries.iter().enumerate() {
        let outcome = parse_key(tables.schema(&spec.table), &spec.key).and_then(|(schema, key)| {
            let params = typed_params(schema, &spec.action, &spec.params)?;
            tables.table_add(schema.name, key, &spec.action, &params)
        });
        if let Err(e) = outcome {
            return Err(format!(
                "entry {i} ({} {}): {e} [{i} of {} applied]",
                spec.table,
                spec.key,
                entries.len()
            ));
        }
    }
    Ok(entries.len())
}

/// Refine a key against its table's declared match kind.
fn parse_key(
    schema: Result<&'static TableSchema, TableError>,
    key: &str,
) -> Result<(&'static TableSchema, TypedKey), TableError> {
    let schema = schema?;
    let key = TypedKey::parse(schema.key, key).map_err(TableError::Value)?;
    Ok((schema, key))
}

/// Refine action parameters against the action's declared signature.
///
/// Named and positional forms converge here, so the pipeline only ever sees
/// values in declaration order with the declared kinds.
fn typed_params(
    schema: &'static TableSchema,
    action: &str,
    params: &Params,
) -> Result<Vec<TypedVal>, TableError> {
    let sig: &ActionSchema = schema
        .action(action)
        .ok_or_else(|| TableError::UnknownAction {
            table: schema.name,
            action: action.to_owned(),
            known: schema.actions.iter().map(|a| a.name.to_owned()).collect(),
        })?;
    let arity = |got: usize| TableError::Arity {
        table: schema.name,
        action: sig.name,
        want: sig.params.len(),
        got,
    };
    match params {
        Params::Positional(given) => {
            if given.len() != sig.params.len() {
                return Err(arity(given.len()));
            }
            given
                .iter()
                .zip(sig.params)
                .map(|(text, p)| TypedVal::parse(p.kind, text).map_err(TableError::Value))
                .collect()
        }
        Params::Named(given) => {
            if given.len() != sig.params.len() {
                return Err(arity(given.len()));
            }
            sig.params
                .iter()
                .map(|p| {
                    let text = given.get(p.name).ok_or_else(|| {
                        TableError::Value(ValueError::Malformed {
                            kind: p.kind,
                            text: format!("missing parameter {:?}", p.name),
                        })
                    })?;
                    TypedVal::parse(p.kind, text).map_err(TableError::Value)
                })
                .collect()
        }
    }
}

/// The listening control socket. Removes its socket file when dropped.
pub struct Server {
    listener: Socket,
    path: PathBuf,
    ctx: Arc<Context>,
}

impl Server {
    /// Bind the control socket at `path`, mode 0600.
    ///
    /// A leftover socket file from a crashed node is removed; a *live* one is
    /// an error, because two nodes sharing a control socket is a mistake worth
    /// failing on (spec S1.6).
    pub fn bind(path: &Path, ctx: Arc<Context>) -> io::Result<Self> {
        if path.exists() {
            if Socket::new(Domain::UNIX, Type::SEQPACKET, None)
                .and_then(|s| s.connect(&SockAddr::unix(path)?))
                .is_ok()
            {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!("another up4d is listening on {}", path.display()),
                ));
            }
            std::fs::remove_file(path)?;
            warn!(path = %path.display(), "removed a stale control socket");
        }
        let listener = Socket::new(Domain::UNIX, Type::SEQPACKET, None)?;
        listener.bind(&SockAddr::unix(path)?)?;
        // Between bind and chmod the socket is world-accessible. Narrow it
        // immediately; the filesystem is the only authorization up4 has.
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        listener.listen(16)?;
        listener.set_read_timeout(Some(ACCEPT_TIMEOUT))?;
        Ok(Self {
            listener,
            path: path.to_owned(),
            ctx,
        })
    }

    /// Where the server is listening.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Serve until `stop` is requested.
    ///
    /// Connections are handled one at a time: control traffic is a human or a
    /// script, never a load source, and serializing it keeps the consistency
    /// story simple.
    pub fn serve(&self, stop: &Stop) -> io::Result<()> {
        let mut buf = Vec::new();
        while !stop.requested() {
            let mut conn = match self.listener.accept() {
                Ok((conn, _)) => conn,
                Err(e) if up4_io::socket::is_transient(&e) => continue,
                Err(e) => return Err(e),
            };
            conn.set_read_timeout(Some(ACCEPT_TIMEOUT))?;
            if let Err(e) = self.converse(&mut conn, &mut buf, stop) {
                warn!("control connection ended: {e}");
            }
        }
        Ok(())
    }

    /// Answer requests on one connection until the peer leaves or goes quiet.
    fn converse(&self, conn: &mut Socket, buf: &mut Vec<u8>, stop: &Stop) -> io::Result<()> {
        let mut idle = Duration::ZERO;
        loop {
            let request = match codec::recv::<Request>(conn, buf) {
                Ok(None) => return Ok(()),
                Ok(Some(r)) => r,
                Err(e) if up4_io::socket::is_transient(&e) => {
                    if stop.requested() {
                        return Ok(());
                    }
                    idle += ACCEPT_TIMEOUT;
                    if idle >= IDLE_TIMEOUT {
                        debug!("closing an idle control connection");
                        return Ok(());
                    }
                    continue;
                }
                Err(e) => return Err(e),
            };
            idle = Duration::ZERO;
            debug!(?request, "control request");
            let response = handle(&self.ctx, request);
            if let Err(e) = codec::send(conn, &response) {
                // A reply too large for a control frame is still an answer.
                codec::send(conn, &Response::error(&e))?;
            }
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}
