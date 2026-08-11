# up4-catalog

Loading a pipeline: the one place all three backends are named.

`up4-engine::catalog` models *what* can be loaded (`Program × Backend` as
closed sums), but it cannot construct the compiled backends without depending
on them, and they depend on it. So the total function lives here, in the crate
above all three, where the dependency graph stays a DAG.

`build` is total: `Selection` is closed and every variant is implemented, so
unlike a name lookup it cannot fail. An unknown pipeline stops at
`Selection::parse`, at configuration time, with the alternatives listed.
