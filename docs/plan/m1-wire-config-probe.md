# M1 — up4-wire + up4-config + probe

Spec: S2 (layout), S4 (wire), S5 (config), S11.1 (probe), S12 (fatal-error
shape). Done-when: unit tests green, probe runs on a stock Linux box (S15 M1).

## Scaffold

- [ ] Workspace `Cargo.toml`: members `crates/*`, `tools`, `benches`;
      `[profile.release] panic = "abort"` (S12), `lto = true`, `codegen-units = 1`.
- [ ] `rust-toolchain.toml`: channel = latest stable at implementation time,
      pinned exactly (S1.7). Edition 2024 workspace-wide.
- [ ] `.gitignore` (`/target`), base CI job: `cargo test`, `clippy -D warnings`,
      `cargo fmt --check`.

## up4-wire (pure, no I/O, no deps)

- [ ] `Hdr { ingress_vport: u16, seq: u32, ts_us: u32 }` — version/flags are
      constants in v1, not fields; illegal versions die in `decode`.
- [ ] `WireError`: closed enum `{ ShortBuffer, BadVersion(u8) }`. No `thiserror`.
- [ ] `encode(&Hdr, &mut [u8; OVERLAY_HDR_LEN])`, `decode(&[u8]) -> Result<Hdr, WireError>`.
      Branch-light, alloc-free, big-endian via `to_be_bytes`/`from_be_bytes`.
- [ ] Constants: `OVERLAY_HDR_LEN = 12`, `INNER_MTU_V4 = 1460`, `INNER_MTU_V6 = 1440`.
- [ ] Tests: every reject case; round-trip property test over a deterministic
      xorshift PRNG loop (~1 M cases). No proptest/quickcheck — closed dep
      list (S2); a seeded loop is the whole requirement.

## up4-config (parse, don't validate)

- [ ] Raw serde mirror struct (`RawConfig`) → one smart constructor
      `Config::from_toml(&str) -> Result<Config, Vec<ConfigError>>` that
      collects **every** violation (S5), never just the first.
- [ ] Domain types make violations unrepresentable after construction:
      `VportId(u16)` (< 65535; 65535 is the reserved punt id),
      `Threads(u8)` (1..=16), `Fabric::{V4,V6}` (default V4).
- [ ] Checks: vport ids unique, peer tuples unique, bind parseable, pipeline
      name ∈ compiled-in registry (registry passed in as `&[&str]` so this
      crate stays engine-agnostic).
- [ ] Build the receive demux map here: `HashMap<SocketAddr, VportId>`,
      read-only after startup (S6.2 step 3). O(1) per packet, no locking.
- [ ] Tests: one test per validation rule, plus a multi-error case asserting
      all violations are listed.

## probe (tools crate, bin `probe`)

- [ ] Probe **logic** lives in `up4-io` (`up4_io::probe`) so `up4d` prints the
      same banner (S11.1) without spawning a process; `tools` bin is a thin
      clap main over it.
- [ ] Collect: kernel release (`libc::uname`), granted SO_RCVBUF/SO_SNDBUF for
      an 8 MiB request (socket2, read back after set), UDP_GRO and UDP_SEGMENT
      setsockopt success, quinn-udp `UdpSocketState` capabilities,
      `/proc/sys/kernel/io_uring_disabled` if readable, cgroup effective CPUs
      (`/sys/fs/cgroup` cpuset, v2 then v1), route MTU to a supplied peer
      (connect a UDP socket, read egress iface, read
      `/sys/class/net/<iface>/mtu`).
- [ ] Output: one JSON object on stdout.

## Decisions

- **serde_json** is in the S2 dependency list, required by S8
  (length-prefixed JSON), S9 (JSONL snapshots), and S11.1 (probe JSON).
- No `smallvec`: preallocated per-vport `Vec<SegDesc>` cleared per batch
  covers S6.3's staging queues (M2).

## Verify

```sh
cargo test -p up4-wire -p up4-config
cargo clippy --workspace --all-targets -- -D warnings
cargo run -p up4-tools --bin probe -- --peer 127.0.0.1 | jq .
```
