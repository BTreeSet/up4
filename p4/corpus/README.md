# Conformance corpora (spec S10)

One directory per P4 program. Each holds the control-plane state a case set
assumes and the cases themselves:

```
p4/corpus/<program>/tables.json   # {"entries": [{table, key, action, params}]}
p4/corpus/<program>/cases.json    # [{name, ingress_port, frame_hex, expect}]
```

A case's `expect` is `{"verdict": "forward"|"broadcast"|"punt"|"drop"}` plus
`egress_port` when the verdict is `forward`, and `frame_hex` when the frame
that comes out must be compared byte for byte.

## Who writes the expectations

Today: `tools/corpus/gen_corpus.py`, an independent model of the P4 source. It
builds each frame and works out what the program says happens to it without
consulting the Rust implementation, so a bug present in only one of the two
shows up as a diff. Regenerate with

```sh
python3 tools/corpus/gen_corpus.py            # write
python3 tools/corpus/gen_corpus.py --check    # verify (CI)
```

Ultimately (spec S10): `tools/bmv2-diff/`, which replays the same cases through
BMv2 and writes the expectations here. When it lands, the Rust side does not
change — `crates/up4-engine/tests/conformance.rs` already reads this format.

## The mask

Before diffing frames, both sides zero **exactly** these fields:

| Field | Offset |
|---|---|
| IPv4 header checksum | `eth(14) + 10` |
| TCP checksum | `eth(14) + ihl*4 + 16` |
| UDP checksum | `eth(14) + ihl*4 + 6` |

Nothing else is masked. up4 never computes or verifies an inner checksum
(spec S1.5), so these fields carry no information; every other byte — TTL,
addresses, payload — must match exactly.

The mask is implemented twice, once per language, because the two runners are
independent by design. The implementations are `mask()` in
`crates/up4-engine/tests/conformance.rs` and the `routed()` helper plus the
`MASK_*` constants in `tools/corpus/gen_corpus.py`. This table is the contract
they both answer to; change it here first.

## Coverage each corpus owes (spec S10)

- every parser branch taken, in both directions of each `select`;
- a truncated-header case per extracted header;
- table hit, table miss, and an entry whose action differs from the default;
- TTL=1 and TTL=0 where the program decrements TTL;
- a minimum-size (60 B) and a maximum-size (1460 B) frame.

`conformance.rs` fails the build if a registered program has no corpus.
