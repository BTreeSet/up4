# up4 docs

Reading order, for humans and agents. Progressive disclosure: stop as soon as
you know enough for the task in front of you.

1. [spec.md](spec.md): implementation spec v1.0. **Artifact of record.**
   When anything else disagrees with it, the spec wins. When it is silent,
   apply its design principles (S3) and ask rather than invent protocol.
2. The milestone plan for the work you are doing; read only that one:

   | Working on | Read | Spec sections |
   |---|---|---|
   | wire format, config, probe | [plan/m1-wire-config-probe.md](plan/m1-wire-config-probe.md) | S4, S5, S11.1 |
   | sockets, rx/tx, pktgen | [plan/m2-io-pktgen.md](plan/m2-io-pktgen.md) | S6, S7.4, S11.2 |
   | ctl channel, counters | [plan/m3-ctl-metrics.md](plan/m3-ctl-metrics.md) | S8, S9, S12 |
   | x4c build, adapter, l2fwd | [plan/m4-engine-l2fwd.md](plan/m4-engine-l2fwd.md) | S7, S10 |
   | l3fwd, punt | [plan/m5-l3fwd-punt.md](plan/m5-l3fwd-punt.md) | S7.2, S8.3, S14 |
   | cluster runs, benches | [plan/m6-cluster-benches.md](plan/m6-cluster-benches.md) | S13, S14 |

3. [deviations.md](deviations.md): where this implementation departs from the
   spec, and why. Read it before concluding that something is missing: the
   x4c build step, the BMv2 differential runner, and the blocking-socket
   wording are all recorded there with the seam that closes each one.

Milestones are sequential (spec S15); each ends runnable. Do not start M(n+1)
with M(n)'s done-when unmet.
