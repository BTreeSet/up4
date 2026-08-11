//! Turning the registry into JSON (spec S9): the `counters` control command
//! and the periodic `up4-metrics-<node>.jsonl` line.

use crate::{Counter, Hist, Histogram, Metrics, VportCounter};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{BufWriter, Write},
    path::{Path, PathBuf},
};

/// One histogram bucket. `le = None` is the unbounded overflow bucket.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Bucket {
    /// Inclusive upper bound, or `null` for the overflow bucket.
    pub le: Option<u32>,
    /// Observations in this bucket.
    pub count: u64,
}

/// A histogram, rendered.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HistogramSnapshot {
    /// Buckets in increasing order, overflow last.
    pub buckets: Vec<Bucket>,
}

impl HistogramSnapshot {
    fn of(h: &Histogram) -> Self {
        let counts = h.read();
        Self {
            buckets: counts
                .iter()
                .enumerate()
                .map(|(i, count)| Bucket {
                    le: Histogram::BOUNDS.get(i).copied(),
                    count: *count,
                })
                .collect(),
        }
    }
}

/// One vport's counters, rendered.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VportSnapshot {
    /// Configured vport id.
    pub id: u16,
    /// Counter name to value, in spec order.
    pub counters: BTreeMap<String, u64>,
}

/// A full counter snapshot.
///
/// Not a consistent cut: see the crate-level note on memory ordering.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Snapshot {
    /// `node.id` from the configuration.
    pub node: String,
    /// Wall-clock microseconds since the Unix epoch when the snapshot was
    /// taken, so JSONL lines can be joined against other experiment traces.
    pub ts_us: u64,
    /// Node-wide counters.
    pub counters: BTreeMap<String, u64>,
    /// Sum of the harness-drop counters, precomputed because it is the number
    /// the acceptance criteria are stated in.
    pub harness_drops: u64,
    /// Per-vport counters.
    pub vports: Vec<VportSnapshot>,
    /// I/O-shape histograms.
    pub histograms: BTreeMap<String, HistogramSnapshot>,
}

impl Metrics {
    /// Read every counter.
    ///
    /// Cost: O(counters + vports); called by the control channel and the
    /// snapshot thread, never on the fast path.
    #[must_use]
    pub fn snapshot(&self, ts_us: u64) -> Snapshot {
        Snapshot {
            node: self.node().to_owned(),
            ts_us,
            counters: Counter::ALL
                .iter()
                .map(|c| (c.name().to_owned(), self.get(*c)))
                .collect(),
            harness_drops: self.harness_drops(),
            vports: self
                .vport_ids()
                .iter()
                .zip(self.vport_blocks())
                .map(|(id, block)| VportSnapshot {
                    id: *id,
                    counters: VportCounter::ALL
                        .iter()
                        .map(|c| (c.name().to_owned(), block.get(*c)))
                        .collect(),
                })
                .collect(),
            histograms: Hist::ALL
                .iter()
                .map(|h| (h.name().to_owned(), HistogramSnapshot::of(self.hist(*h))))
                .collect(),
        }
    }
}

/// Appends snapshots to `up4-metrics-<node>.jsonl`, one JSON object per line.
///
/// Owns the file, not the schedule: the caller decides when to write, so the
/// periodic thread and a shutdown's final snapshot use the same path.
#[derive(Debug)]
pub struct SnapshotWriter {
    path: PathBuf,
    out: BufWriter<File>,
}

impl SnapshotWriter {
    /// Open (creating, appending) the JSONL file for `node` under `dir`.
    pub fn open(dir: &Path, node: &str) -> std::io::Result<Self> {
        let path = dir.join(format!("up4-metrics-{node}.jsonl"));
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self {
            path,
            out: BufWriter::new(file),
        })
    }

    /// Where lines are being written.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one snapshot and flush, so a `kill -KILL` cannot lose a line
    /// that was already reported as written.
    pub fn append(&mut self, snap: &Snapshot) -> std::io::Result<()> {
        serde_json::to_writer(&mut self.out, snap)?;
        self.out.write_all(b"\n")?;
        self.out.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use up4_config::Config;

    fn metrics() -> Metrics {
        let src = r#"
[node]
id = "a"
bind = "127.0.0.1:1"
pipeline = "p"
ctl_socket = "/tmp/t.sock"
[[vport]]
id = 4
peer = "127.0.0.1:2"
"#;
        let cfg = Config::from_toml(src, &["p"]).expect("fixture is valid");
        Metrics::new(&cfg.node.id, &cfg.vports)
    }

    #[test]
    fn snapshot_round_trips_through_json() {
        let m = metrics();
        m.add(Counter::RxBadHeader, 3);
        m.hist(Hist::GroSegmentsPerRead).record(8);
        let snap = m.snapshot(42);
        let text = serde_json::to_string(&snap).expect("serializable");
        assert_eq!(
            serde_json::from_str::<Snapshot>(&text).expect("parses"),
            snap
        );
        assert!(text.contains("\"rx_bad_header\":3"), "{text}");
        assert!(text.contains("\"harness_drops\":3"), "{text}");
    }

    #[test]
    fn snapshot_names_every_counter_even_at_zero() {
        let snap = metrics().snapshot(0);
        assert_eq!(snap.counters.len(), Counter::ALL.len());
        assert_eq!(snap.vports.len(), 1);
        assert_eq!(snap.vports[0].id, 4);
        assert_eq!(snap.vports[0].counters.len(), VportCounter::ALL.len());
        assert_eq!(snap.histograms.len(), Hist::ALL.len());
        assert_eq!(
            snap.histograms["gro_segments_per_read"]
                .buckets
                .last()
                .map(|b| b.le),
            Some(None)
        );
    }

    #[test]
    fn writer_appends_one_line_per_snapshot() {
        let dir = std::env::temp_dir().join(format!("up4-metrics-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("tempdir");
        let m = metrics();
        let mut w = SnapshotWriter::open(&dir, "a").expect("open");
        w.append(&m.snapshot(1)).expect("append");
        w.append(&m.snapshot(2)).expect("append");
        let text = std::fs::read_to_string(w.path()).expect("read back");
        assert_eq!(text.lines().count(), 2);
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }
}
