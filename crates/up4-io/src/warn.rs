//! Rate-limited warnings (spec S12).
//!
//! The datapath must never log per packet, but a condition that fires once is
//! exactly what an operator needs to see. This is the compromise the spec
//! names: log the first occurrence, then a count every ten seconds, and keep
//! counting silently in between.

use crate::clock;
use std::sync::atomic::{AtomicU64, Ordering};

/// How long a condition class stays silent between reports.
pub const WARN_INTERVAL_US: u64 = 10_000_000;

/// One condition class's occurrence counter and next-report deadline.
#[derive(Debug, Default)]
pub struct WarnRate {
    count: AtomicU64,
    next_us: AtomicU64,
}

impl WarnRate {
    /// A counter that has never fired.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            count: AtomicU64::new(0),
            next_us: AtomicU64::new(0),
        }
    }

    /// Record an occurrence.
    ///
    /// Returns the running total when the caller should log, and `None` when it
    /// should stay quiet. The first occurrence always reports.
    ///
    /// Cost: one relaxed fetch-add, and a clock read only when the interval may
    /// have elapsed.
    #[inline]
    pub fn tick(&self) -> Option<u64> {
        let count = self.count.fetch_add(1, Ordering::Relaxed) + 1;
        let now = clock::monotonic_us();
        let next = self.next_us.load(Ordering::Relaxed);
        if count == 1 || now >= next {
            // A race here logs twice, which is strictly better than a lock on a
            // path whose purpose is to stay out of the way.
            self.next_us
                .store(now + WARN_INTERVAL_US, Ordering::Relaxed);
            return Some(count);
        }
        None
    }

    /// Occurrences so far.
    #[must_use]
    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_occurrence_always_reports() {
        let w = WarnRate::new();
        assert_eq!(w.tick(), Some(1));
    }

    #[test]
    fn subsequent_occurrences_are_counted_quietly() {
        let w = WarnRate::new();
        assert_eq!(w.tick(), Some(1));
        for _ in 0..1000 {
            assert_eq!(w.tick(), None);
        }
        assert_eq!(w.count(), 1001);
    }

    #[test]
    fn the_interval_reports_the_running_total() {
        let w = WarnRate::new();
        w.tick();
        w.tick();
        // Pull the deadline into the past rather than sleeping ten seconds.
        w.next_us.store(0, Ordering::Relaxed);
        assert_eq!(w.tick(), Some(3));
        assert_eq!(w.tick(), None, "and goes quiet again");
    }
}
