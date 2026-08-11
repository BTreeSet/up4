# up4-ctl

The control channel (spec S8): a `SOCK_SEQPACKET` Unix socket carrying
length-prefixed JSON, the `up4ctl` CLI over it, and the typed table shim behind
it.

`Request`/`Response` are closed sums, so the protocol is exhaustively handled on
both ends and a round-trip test exists for every shape. Added after a serde
tagged-newtype encoding failed only over the socket and not in unit tests.

Beyond the spec's command list it carries the conveniences experiments actually
need (`tables`, `table default`, `table clear`, `table load`, and `--tables` at
startup; deviation D6). None of it adds protocol: each is the same typed shim
call the specified commands make.

Filesystem permissions are the boundary; the socket is created 0600.
