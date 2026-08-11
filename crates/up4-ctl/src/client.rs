//! The control client: what `up4ctl` and the integration tests speak.

use crate::{
    codec,
    protocol::{Request, Response},
};
use socket2::{Domain, SockAddr, Socket, Type};
use std::{io, path::Path, time::Duration};

/// How long a client waits for a reply before giving up.
const CALL_TIMEOUT: Duration = Duration::from_secs(10);

/// A connection to a node's control channel.
#[derive(Debug)]
pub struct Client {
    sock: Socket,
    buf: Vec<u8>,
}

impl Client {
    /// Connect to the control socket at `path`.
    pub fn connect(path: &Path) -> io::Result<Self> {
        let sock = Socket::new(Domain::UNIX, Type::SEQPACKET, None)?;
        sock.connect(&SockAddr::unix(path)?).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("cannot reach up4d at {}: {e}", path.display()),
            )
        })?;
        sock.set_read_timeout(Some(CALL_TIMEOUT))?;
        Ok(Self {
            sock,
            buf: Vec::new(),
        })
    }

    /// Send one request and read its reply.
    pub fn call(&mut self, request: &Request) -> io::Result<Response> {
        codec::send(&mut self.sock, request)?;
        codec::recv(&mut self.sock, &mut self.buf)?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "up4d closed the control connection",
            )
        })
    }
}
