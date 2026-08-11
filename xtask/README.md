# xtask

up4's generation toolchain: `cargo xtask {check,generate,verify}`.

Two backends are compiler output whose artifacts are committed, so the
repository builds without either P4 compiler present. That creates exactly one
failure mode — a `.p4` edited without regenerating — and this exists to make it
detectable and fixable.

One `realize` runs the compilers into a scratch directory and returns
`(produced, committed)` pairs; a `Mode` folds those pairs three ways. So
"regenerate" and "is this checkout stale?" are one procedure consumed twice, not
two that must be kept in step.

Userspace, no root: micromamba is a static binary, p4c builds from source inside
its prefix, and clang comes from that prefix rather than the host — necessary,
because objects are compared byte for byte and an unpinned compiler would make a
clean checkout look stale.

`verify` reports; it never rewrites. The CI token is read-only by design, so the
fix (`cargo xtask generate`) is a human's move.
