# up4-metrics

Every counter the switch keeps (spec S9), as closed enums with an `ALL` array.

Counters are an enum rather than string keys so that the snapshot writer, the
control channel, and the tests iterate the same set, and a new counter cannot be
added without appearing everywhere it belongs. That is what makes spec A5's
claim checkable: every discarded frame increments a *named* counter, so loss is
attributable rather than merely small.

Flat `AtomicU64` registry, power-of-two histograms. No allocation on the fast
path.
