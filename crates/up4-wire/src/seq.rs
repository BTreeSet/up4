//! Per-flow sequence accounting (spec S6.2 step 5).
//!
//! up4 never buffers or reorders: it *records*. This module is the pure
//! classifier that the receive path drives, kept here (rather than in the I/O
//! shell) because it is total, allocation-free, and worth testing on its own.
//!
//! Cost: O(1) time, 8 bytes of state per vport.

/// Frames arriving at most this far behind the expectation are late, not lost.
pub const REORDER_WINDOW: u32 = 1024;

/// A sequence number on the wire: a counter modulo 2^32.
///
/// Wrapping is part of the contract, so the arithmetic lives on the type and
/// no caller ever compares two of these with `<`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Seq(u32);

impl Seq {
    /// Wrap a raw counter value from the wire.
    #[inline]
    #[must_use]
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    /// The raw counter value, for encoding.
    #[inline]
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }

    /// The next value in the sequence, wrapping at 2^32.
    #[inline]
    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0.wrapping_add(1))
    }

    /// Signed distance `self - other`, interpreting the wrapped difference as
    /// the shortest path around the ring. Positive means `self` is ahead.
    #[inline]
    #[must_use]
    pub const fn delta(self, other: Self) -> i32 {
        self.0.wrapping_sub(other.0) as i32
    }
}

/// What a received sequence number says about the flow.
///
/// Closed: the receive path matches exhaustively and every arm maps to exactly
/// one counter (spec S9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeqEvent {
    /// Exactly the expected number (or the first frame seen on this flow).
    InOrder,
    /// Ahead of expectation: this many frames were skipped.
    Gap(u32),
    /// Behind expectation: a late frame, or a peer that restarted its counter.
    Reorder,
}

/// Per-vport receive expectation.
///
/// `None` means "no frame seen yet", which is why the first frame can never be
/// misreported as a 4-billion-frame gap.
#[derive(Clone, Copy, Debug, Default)]
pub struct SeqTracker {
    expected: Option<Seq>,
}

impl SeqTracker {
    /// A tracker that has seen nothing.
    #[must_use]
    pub const fn new() -> Self {
        Self { expected: None }
    }

    /// The next sequence number this flow expects, if any frame has arrived.
    #[must_use]
    pub const fn expected(&self) -> Option<Seq> {
        self.expected
    }

    /// Classify `seq` and advance the expectation.
    ///
    /// A frame behind the expectation but within [`REORDER_WINDOW`] is late:
    /// the expectation is left alone so the frames still in flight ahead of it
    /// are not counted as a gap. A frame further behind than that is a peer
    /// that restarted (or a wrap-scale jump); the expectation resynchronizes so
    /// the flow does not report every subsequent frame as reordered forever.
    #[inline]
    pub fn observe(&mut self, seq: Seq) -> SeqEvent {
        let Some(expected) = self.expected else {
            self.expected = Some(seq.next());
            return SeqEvent::InOrder;
        };
        match seq.delta(expected) {
            0 => {
                self.expected = Some(seq.next());
                SeqEvent::InOrder
            }
            ahead if ahead > 0 => {
                self.expected = Some(seq.next());
                SeqEvent::Gap(ahead.unsigned_abs())
            }
            behind if behind.unsigned_abs() <= REORDER_WINDOW => SeqEvent::Reorder,
            _ => {
                self.expected = Some(seq.next());
                SeqEvent::Reorder
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observe_all(start: u32, seqs: &[u32]) -> Vec<SeqEvent> {
        let mut t = SeqTracker::new();
        t.observe(Seq::new(start));
        seqs.iter().map(|s| t.observe(Seq::new(*s))).collect()
    }

    #[test]
    fn first_frame_is_in_order_whatever_its_value() {
        let mut t = SeqTracker::new();
        assert_eq!(t.observe(Seq::new(0xdead_beef)), SeqEvent::InOrder);
        assert_eq!(t.expected(), Some(Seq::new(0xdead_bef0)));
    }

    #[test]
    fn contiguous_run_is_in_order() {
        assert!(
            observe_all(0, &[1, 2, 3, 4])
                .iter()
                .all(|e| *e == SeqEvent::InOrder)
        );
    }

    #[test]
    fn gap_reports_the_number_of_missing_frames() {
        assert_eq!(observe_all(10, &[14]), vec![SeqEvent::Gap(3)]);
    }

    #[test]
    fn late_frame_is_reorder_and_does_not_disturb_expectation() {
        // 10, then 14 (gap of 3), then the three late ones arrive.
        assert_eq!(
            observe_all(10, &[14, 11, 12, 13, 15]),
            vec![
                SeqEvent::Gap(3),
                SeqEvent::Reorder,
                SeqEvent::Reorder,
                SeqEvent::Reorder,
                SeqEvent::InOrder,
            ]
        );
    }

    #[test]
    fn counter_wrap_is_in_order_not_a_gap() {
        assert_eq!(
            observe_all(u32::MAX, &[0, 1]),
            vec![SeqEvent::InOrder, SeqEvent::InOrder]
        );
    }

    #[test]
    fn far_behind_resynchronizes() {
        // A peer restart: one Reorder, then the new run is in order.
        assert_eq!(
            observe_all(1_000_000, &[0, 1, 2]),
            vec![SeqEvent::Reorder, SeqEvent::InOrder, SeqEvent::InOrder]
        );
    }

    #[test]
    fn reorder_window_boundary_is_exact() {
        let mut t = SeqTracker::new();
        t.observe(Seq::new(REORDER_WINDOW + 10));
        // expected = W + 11; a frame exactly W behind it is still "late"...
        assert_eq!(t.observe(Seq::new(11)), SeqEvent::Reorder);
        assert_eq!(t.expected(), Some(Seq::new(REORDER_WINDOW + 11)));
        // ...and one further back resynchronizes.
        assert_eq!(t.observe(Seq::new(10)), SeqEvent::Reorder);
        assert_eq!(t.expected(), Some(Seq::new(11)));
    }

    #[test]
    fn delta_is_shortest_path_around_the_ring() {
        assert_eq!(Seq::new(0).delta(Seq::new(u32::MAX)), 1);
        assert_eq!(Seq::new(u32::MAX).delta(Seq::new(0)), -1);
    }
}
