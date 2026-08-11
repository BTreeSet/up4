# M4: x4c build integration + adapter + table shim + l2fwd

Spec: S7 (engine), S10 (conformance). Done-when: l2fwd conformance corpus
passes bit-identically post-masking (S15 M4).

## x4c build step (up4-engine/build.rs)

- [ ] Pin the x4c git revision in a `const X4C_REV: &str`; build script
      invokes x4c on every `p4/programs/*/*.p4`, emitting
      `src/gen/<program>.rs` (vendored, S2).
- [ ] Compile-time refusal (S7.2): grep P4 source for SoftNPU/psa
      queue-depth/queue-delay intrinsic metadata and meter externs →
      `panic!` with "no traffic manager in up4 v1". A substring denylist is
      the whole mechanism; do not build a P4 parser in build.rs.
- [ ] Engine registry: `fn registry() -> &[(&str, fn() -> Box<dyn Engine>)]`
      keyed by program name; up4-config validates `pipeline` against it (M1
      seam), up4d instantiates per shard.

## Adapter (Pipeline → Engine)

- [ ] SoftNPU-model ingress metadata from `ingress_vport` + `rx_ts_us`.
- [ ] Egress mapping (S7.2): `drop` → `Drop`; `broadcast` → `Broadcast`;
      port 65535 → `Punt`; else `Forward(port)`.
- [ ] Checksum zero-fill (S1.5), v1 unconditional: hand-rolled EtherType /
      IP-proto sniff at canonical offsets (~20 lines). **Not** etherparse,
      which is dev/test-only per S2. This is the only inner-packet touch the
      harness performs.

## Table shim (S7.3)

- [ ] `TypedKey` / `TypedVal` closed enums (exact, range, LPM, ternary
      if x4c emits it); endianness fully encapsulated: exact+range LE, LPM
      wire-order BE, params LE.
- [ ] `table_add / table_remove / table_dump` over generated table state,
      serialized through a `Mutex` held only during control operations.
      Document consistency: atomic per entry, not per batch; in-flight
      packets may see either version.
- [ ] Endianness tests against fixed byte vectors (S13.1): these are the
      contract, so pin them hard.
- [ ] Activate the M3 `table-add/del/dump` arms against the shim.

## l2fwd + conformance

- [ ] `p4/programs/l2fwd/l2fwd.p4`: static MAC table, broadcast on miss.
- [ ] `p4/corpus/l2fwd/*.json` meeting S10 minimums: every parser branch,
      truncated-header per extracted header, hit/miss/default-action,
      60 B and 1460 B frames.
- [ ] `tools/bmv2-diff/` (Python, CI container only): replay corpus through
      BMv2, write expectations file into the corpus dir.
- [ ] `conformance.rs`: same cases through `Engine` directly, no sockets;
      mask IPv4 header checksum + TCP/UDP checksums on **both** sides, diff
      the rest bit-identically. Mask function shared between the Rust test
      and the Python runner (two implementations, one documented field list;
      keep them adjacent in the corpus README).
- [ ] CI gate: missing corpus or failed diff fails the build (S10).

## Verify

```sh
cargo test -p up4-engine            # shim endianness + conformance.rs
tools/bmv2-diff/run.sh l2fwd        # in CI container
```
