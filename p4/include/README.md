# Vendored architecture models

These are not up4's files. They are the architecture models the two P4
compilers define, vendored so a build is reproducible without cloning either
compiler, and so `#include <...>` resolves next to the program that uses it.

| path | upstream | used by |
|---|---|---|
| `softnpu/core.p4`, `softnpu/softnpu.p4` | `oxidecomputer/p4`, `test/src/p4/` | `x4c` (the `x4c` backend, and the source of record the `native` backend renders) |
| `ubpf/core.p4`, `ubpf/ubpf_model.p4` | `p4lang/p4c`, `p4include/` | `p4c --target ubpf` (the `ubpf` backend) |

Do not edit them. If a model changes upstream, re-vendor and let the
conformance corpora say whether anything moved.
