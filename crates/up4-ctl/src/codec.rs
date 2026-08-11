//! Message framing (spec S8.1).
//!
//! `SOCK_SEQPACKET` already preserves message boundaries; the `u32` length
//! prefix the spec mandates rides along and is *checked*, which turns a
//! truncated read — the one way a datagram socket can silently lie — into a
//! loud error instead of a parse failure at some arbitrary byte.

use serde::{Serialize, de::DeserializeOwned};
use socket2::Socket;
use std::io::{self, Read, Write};

/// Largest message either side will send or accept.
///
/// AF_UNIX datagrams are bounded by the socket send buffer, which an
/// unprivileged process cannot raise past `net.core.wmem_max`. 256 KiB is
/// comfortably under that on a stock kernel and holds a several-thousand-entry
/// table dump; anything larger is refused with an explanation rather than
/// truncated (spec S1.6).
pub const MAX_FRAME: usize = 256 * 1024;

const LEN_PREFIX: usize = 4;

/// Serialize and send one message.
pub fn send<T: Serialize>(sock: &mut Socket, msg: &T) -> io::Result<()> {
    let body = serde_json::to_vec(msg).map_err(io::Error::other)?;
    let len = u32::try_from(body.len())
        .ok()
        .filter(|n| *n as usize <= MAX_FRAME)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "message of {} B exceeds the {MAX_FRAME} B control frame limit",
                    body.len()
                ),
            )
        })?;
    let mut framed = Vec::with_capacity(LEN_PREFIX + body.len());
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(&body);
    sock.write_all(&framed)
}

/// Receive one message, or `None` when the peer closed the connection.
///
/// `buf` is the caller's reusable scratch space; it is sized to [`MAX_FRAME`]
/// on first use and never grows after that.
pub fn recv<T: DeserializeOwned>(sock: &mut Socket, buf: &mut Vec<u8>) -> io::Result<Option<T>> {
    buf.resize(LEN_PREFIX + MAX_FRAME, 0);
    let n = sock.read(buf)?;
    if n == 0 {
        return Ok(None);
    }
    let Some(prefix) = buf.first_chunk::<LEN_PREFIX>() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "control frame has no length prefix",
        ));
    };
    let len = u32::from_be_bytes(*prefix) as usize;
    if LEN_PREFIX + len != n {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "control frame declares {len} B, {} B arrived",
                n - LEN_PREFIX
            ),
        ));
    }
    serde_json::from_slice(&buf[LEN_PREFIX..n])
        .map(Some)
        .map_err(io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;
    use socket2::{Domain, Type};

    fn pair() -> (Socket, Socket) {
        let (a, b) = Socket::pair(Domain::UNIX, Type::SEQPACKET, None).expect("socketpair");
        (a, b)
    }

    #[test]
    fn a_message_round_trips() {
        let (mut a, mut b) = pair();
        send(&mut a, &crate::Request::Ping).expect("send");
        let mut buf = Vec::new();
        let got: Option<crate::Request> = recv(&mut b, &mut buf).expect("recv");
        assert_eq!(got, Some(crate::Request::Ping));
    }

    #[test]
    fn message_boundaries_are_preserved_across_a_burst() {
        let (mut a, mut b) = pair();
        for table in ["one", "two", "three"] {
            send(
                &mut a,
                &crate::Request::TableDump {
                    table: table.to_owned(),
                },
            )
            .expect("send");
        }
        let mut buf = Vec::new();
        for table in ["one", "two", "three"] {
            let got: Option<crate::Request> = recv(&mut b, &mut buf).expect("recv");
            assert_eq!(
                got,
                Some(crate::Request::TableDump {
                    table: table.to_owned()
                })
            );
        }
    }

    #[test]
    fn a_closed_peer_reads_as_end_of_stream() {
        let (a, mut b) = pair();
        drop(a);
        let mut buf = Vec::new();
        let got: Option<crate::Request> = recv(&mut b, &mut buf).expect("recv");
        assert_eq!(got, None);
    }

    #[test]
    fn an_oversized_message_is_refused_before_it_is_sent() {
        let (mut a, _b) = pair();
        let huge = crate::Request::TableDel {
            table: "t".into(),
            key: "x".repeat(MAX_FRAME),
        };
        let err = send(&mut a, &huge).expect_err("refused");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn a_frame_whose_prefix_disagrees_with_its_body_is_rejected() {
        let (mut a, mut b) = pair();
        a.write_all(&[0, 0, 0, 99, 1, 2, 3]).expect("write");
        let mut buf = Vec::new();
        let err = recv::<crate::Request>(&mut b, &mut buf).expect_err("rejected");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
