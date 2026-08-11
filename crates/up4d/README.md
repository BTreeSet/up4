# up4d

The daemon: the startup order, the shard threads, and the shutdown path.

Ordering is the whole content of `main`: block signals before spawning anything
that could receive one, probe and print the banner, parse the config, build the
pipeline, load startup tables, bind, spawn shards, start the control channel,
then wait — and unwind in reverse, reporting any shard panic rather than
swallowing it.

`tests/` also holds the repository's own invariants, as tests rather than CI
steps so they hold on a developer's machine:

- `unsafe_audit.rs` — every use of `unsafe` is on an allowlist with an exact
  site count and a warrant that must be true of the path.
- `ci_cache_keys.rs` — a CI cache key is exactly the cargo profile whose
  artifacts the entry holds.
- `e2e.rs` — two real `up4d` processes forwarding over loopback, unprivileged.
