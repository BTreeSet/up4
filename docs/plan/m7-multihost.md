# M7: all three backends across two hosts, with real traffic

Spec: S1.1 (no privileges), S13.3 (integration), S14 A2/A5/A6, S17.
Decisions: [ADR-007](../decisions.md#adr-007--multi-host-validation-uses-containers-not-sudo-ip-netns).

**Done when:** every backend forwards real traffic between two containers in
separate network namespaces, over a 1500-MTU veth/bridge path, with `up4d`
running as a non-root user, and both nodes' counters reconcile — in CI, on
every push.

This is the definition of done for the three-paths work. M6's cluster runs
(real NICs, throughput targets) remain separate and outstanding; M7 does not
replace them and does not try to.

---

## Why this exists, in one paragraph

Everything up4 has measured so far is loopback: one namespace, `lo`, MTU 65536,
no driver. That path omits segmentation, a netdev transmit path, and a second
network stack. "Three backends work" is currently a claim about
`Engine::process` and a socket on the same host. M7 makes it a claim about a
switch.

---

## Topology

```
  ┌─ container n1 (netns A) ────────┐      ┌─ container n2 (netns B) ────────┐
  │  pktgen  ──►  up4d A            │      │  up4d B  ──►  sink              │
  │               vport 0 ◄─ pktgen │      │  vport 0 ─► sink                │
  │               vport 1 ──────────┼─veth─┼──────────► vport 1              │
  └─────────────────────────────────┘  ▲   └─────────────────────────────────┘
                                       │
                          docker bridge, MTU 1500, 172.28.0.0/24
```

n1 is `172.28.0.11`, n2 is `172.28.0.12`. Frames travel
`pktgen → A → B → sink`, crossing the bridge exactly once, so each frame is
routed by both nodes and the inner TTL falls by two.

---

## The privilege boundary — read this before writing any step

Spec S1.1 says up4 must never require network namespaces. M7 uses them. Both
are true, and keeping them true is the single thing most likely to go wrong
here.

| Actor | May create namespaces | Must be unprivileged |
|---|---|---|
| The harness (workflow, `scripts/multihost.sh`) | yes | no |
| `up4d`, `up4ctl`, `pktgen`, `probe` | **never** | **yes** |

Concretely:

- The harness calls `docker network create` and `docker run`. Docker gives each
  container a namespace; nothing calls `unshare`, `setns`, or `ip netns`.
- Containers run with `--user "$(id -u):$(id -g)"`, and the run **asserts**
  `id -u` is not 0 inside each container before starting `up4d`. A container
  that ran `up4d` as root would pass every functional assertion in this
  document while retiring the only claim up4 exists to make.
- No `--privileged`, no `--cap-add`, no `--network host`, no `--sysctl`.

**If a step seems to need any of those, the step is wrong.** Stop and say so
rather than adding the flag. There is no forwarding behaviour in up4 that
requires a capability; if one appears to, the cause is a topology or MTU
mistake, not a missing privilege.

---

## Steps

### 1. Pin the runner and the image to the same distribution

- [ ] `runs-on: ubuntu-24.04` — **not** `ubuntu-latest`.
- [ ] Container image `ubuntu:24.04`.

The binaries are built on the runner and bind-mounted into the containers, so
the runner's glibc and the image's glibc must match. `ubuntu-latest` moves
between releases without notice; a mismatch shows up as a loader error inside
the container that reads like anything but a version skew.

### 2. Build once, on the runner

- [ ] `cargo build --release --workspace`
- [ ] Bind-mount `target/release/` into both containers read-only.

Do not build inside the containers. One build, two runners of it, is what makes
the two nodes provably the same code.

### 3. Create the network and the containers

- [ ] `docker network create --subnet 172.28.0.0/24 --opt com.docker.network.driver.mtu=1500 up4net`
- [ ] Start `n1` at `172.28.0.11` and `n2` at `172.28.0.12`, both
      `--user "$(id -u):$(id -g)"`, both with `target/release` mounted.
- [ ] Assert inside each: `test "$(id -u)" -ne 0`.
- [ ] Assert inside each: the interface facing `up4net` reports MTU 1500, and
      the peer address is **not** in `127.0.0.0/8`.

The last assertion is the one that proves this is not loopback wearing a
costume. Without it, a misconfigured topology that silently fell back to
localhost would produce a green run that proves nothing.

### 4. Run the probe in both containers and attach the output

- [ ] `probe --peer <other node> --pretty` in each, JSON captured as a CI
      artifact.

S17 says environmental assumptions are probed, not hardcoded. A veth path may
report different GRO/GSO support from `lo`; that difference is a *result*, not
a failure, and it is the context every other number in this run needs.

### 5. For each backend, run the scenario

For `backend` in `native`, `x4c`, `ubpf`:

- [ ] Start `up4d --config <node>.toml --tables routes.json --backend $backend`
      in each container.
- [ ] Wait for both control sockets to answer `ping` (bounded wait, then fail —
      no unbounded loops).
- [ ] Offer a fixed, known count of frames from `pktgen` at a **modest** rate.
- [ ] Collect `up4ctl counters --json` from both nodes via `docker exec`.
- [ ] Assert the checks below.
- [ ] `up4ctl shutdown` both; assert exit 0.

### 6. Record, do not gate, throughput

- [ ] Append the observed rate per backend to `benches/RESULTS.md`, labelled
      with the runner and "shared CI runner, not a benchmark platform".

---

## Validation standard

An assertion that cannot fail is not a test. Each of these must be able to go
red, and the reason it would go red is named.

| # | Assertion | Fails when |
|---|---|---|
| V1 | `id -u` is non-zero in both containers | someone adds a privilege to make a step work |
| V2 | Peer address outside `127.0.0.0/8`, MTU 1500 | the topology silently collapsed to loopback |
| V3 | Frames arriving at the sink equal frames offered, minus accounted loss | forwarding is broken, or a node is dropping silently |
| V4 | `rx_seq_gap_total` plus harness drop counters account for ≥ 99% of any missing frames | a discard path exists that no counter names (S1.6) |
| V5 | Inner TTL fell by exactly 2; destination MAC rewritten per route; IPv4 and transport checksums zero-filled | a backend's envelope is not being applied (ADR-003) |
| V6 | All three backends produce **identical** sink-side frame bytes | the backends have diverged where the corpus mask cannot see |
| V7 | Both nodes exit 0 on `up4ctl shutdown`, and a final counter snapshot is written | S14 A6 regressed |

V6 is the one worth protecting. The conformance corpus compares backends after
masking the checksums; this comparison happens on the wire, after a real
round trip, with nothing masked at all. It is the strongest statement available
that the three paths are one program.

---

## What this milestone does *not* claim

State these in `RESULTS.md` next to any number this run produces, because a
reader will otherwise assume them:

- **Not a throughput result.** A shared GitHub runner is 4 vCPU carrying two
  up4 nodes, a generator, a sink, and a bridge. Numbers from it bound the
  harness on that runner and nothing else. Never add a performance threshold to
  this job; a flaky perf gate teaches everyone to ignore CI.
- **Not a NIC.** veth and a bridge are software. There is no DMA, no PCIe, no
  interrupt coalescing, no hardware offload. It is much closer to a real path
  than `lo` — there is a driver, a 1500-byte MTU, and two network stacks — but
  it is not the cluster. A1/A2 in [m6](m6-cluster-benches.md) remain the only
  throughput acceptance.
- **Not multi-machine.** Two namespaces on one kernel share a scheduler, a page
  cache, and a clock. Nothing here exercises clock skew, asymmetric routing, or
  a fabric with more than one path.

---

## Do not

- Do not add `--privileged`, `--cap-add`, `--network host`, or `sudo` to make a
  step pass.
- Do not gate the job on a packets-per-second number.
- Do not build inside the containers.
- Do not add a per-test timeout to paper over a hang. A hang is a correctness
  bug; find it. (This has bitten this repository once already: a bounded lossy
  ring drained with an unbounded loop.)
- Do not skip a backend because it is slow. `x4c` forwards about 3.2 kpps and
  that is fine — offer it fewer frames, do not exclude it. A backend excluded
  from the multi-host run is a backend with no multi-host evidence.

## Verify

```sh
# locally, same shape as CI (Docker required; still no root)
./scripts/multihost.sh                     # all three backends, asserts V1-V7
docker network rm up4net                   # cleanup is the script's job too
```
