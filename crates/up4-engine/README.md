# up4-engine

The pipeline layer (spec S7): the two contracts a P4 program is executed behind,
the primitives it is executed with, and the `native` backend written against
them.

- `Engine`: one per shard thread, `&mut self`, one frame in, a `Verdict` out.
- `Pipeline`: the shared, control-plane-facing half: owns tables, mints engines.
- `catalog`: `Program × Backend` as closed sums, so selecting a pipeline is a
  total function rather than a name lookup that can fail at run time.
- `table`: copy-on-write RCU (`Shared`/`Cached`): lock-free readers, one
  `Acquire` load per access, an `Arc` clone only on the frame that first
  observes a control-plane change.
- `frame`: `FrameCtx`, a window with headroom, whose operations are total.

`#![forbid(unsafe_code)]`, and that is load-bearing rather than aspirational:
it is why the two compiled backends live in their own crates.
