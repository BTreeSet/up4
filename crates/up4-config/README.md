# up4-config

`up4.toml` → a value in which no configuration error is representable (spec S5).

Parse, don't validate: a wide serde mirror accepts anything TOML-shaped, and one
smart constructor refines it into `Config`, collecting **every** violation
rather than stopping at the first — an operator fixing a config file wants the
whole list. Past that boundary `VportId`, `Threads`, and the peer-to-vport demux
map are correct by construction.

Knows nothing about pipelines: the set of legal names arrives as a parameter, so
this crate does not depend on the engine.
