# up4-tools

Two binaries for driving experiments (spec S11).

- `probe`: what this machine will actually do: kernel, granted socket buffers,
  GRO/GSO support, cgroup CPUs, route MTU. One JSON object. Printed at `up4d`
  startup too, so a result is never recorded without the machine it came from.
- `pktgen`: token-bucket paced generator with a receiver that checks sequence
  numbers, so loss is measured rather than inferred. Percentiles by index over a
  sorted sample; no histogram dependency.
