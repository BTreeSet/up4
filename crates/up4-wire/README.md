# up4-wire

The 12-byte overlay header every frame carries between nodes (spec S4), and the
sequence accounting that turns gaps into loss numbers.

Pure: no I/O, no allocation, no dependencies, `#![forbid(unsafe_code)]`. Encode
and decode are total functions over `[u8; 12]`, so the fabric's format has one
definition and one place to get it wrong. A round-trip property test over a
seeded PRNG covers a million cases.

Separate from `up4-io` because the format is a value, not an effect: the
harness, the traffic generator, and the tests all need it, and none of them
should need a socket to get it.
