# up4-io

The I/O shell (spec S6): sockets, the receive/transmit datapath, clocks,
signals, the startup probe, and the punt queue.

Every syscall in up4 is here, and so is every use of `unsafe` in the shipped
switch — each site on the allowlist with the call it makes. Keeping the shell
thin and named is what lets everything above it be pure.

Batched `recvmmsg` with GRO segment walking, GSO transmit, a preallocated arena,
and a documented headroom invariant that makes "≥ 64 bytes in front of every
segment" true with a single copy. No per-frame allocation, proven by a counting
allocator over 20 480 frames.

The socket is non-blocking with a `poll(2)` readiness wait rather than blocking
(deviation D7): `recvmmsg` without `MSG_WAITFORONE` waits for *all* messages,
which stalls a shard on a batch that will not fill.
