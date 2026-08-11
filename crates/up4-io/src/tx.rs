//! Transmit staging (spec S6.3).
//!
//! Each destination vport owns one preallocated, contiguous buffer. Staging a
//! frame appends `[overlay header][inner frame]` to it, which is exactly the
//! layout `UDP_SEGMENT` wants — so a batch of same-size frames leaves as one
//! syscall, and the memory it leaves from is the memory it was staged into. No
//! second copy, no allocation after startup, and a bounded queue by
//! construction: staging past [`crate::socket::TX_BATCH`] segments is
//! impossible, not merely unlikely.

use crate::socket::{GSO_MAX_BYTES, TX_BATCH};
use up4_wire::OVERLAY_HDR_LEN;

/// One GSO-compatible span of a staging buffer.
///
/// A span is a maximal run of equal-length segments, optionally ending in one
/// shorter segment — precisely what the kernel accepts as a single segmented
/// datagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Run {
    /// Byte offset of the run within the staging buffer.
    pub start: usize,
    /// End offset, exclusive.
    pub end: usize,
    /// Segments in the run.
    pub count: usize,
    /// The segment size to advertise; the final segment may be shorter.
    pub segment_size: usize,
}

/// One destination's staged segments.
#[derive(Debug)]
pub struct TxQueue {
    buf: Box<[u8]>,
    lens: Vec<u16>,
    used: usize,
    /// Largest segment this queue accepts: overlay header plus the fabric's
    /// inner MTU. Staging is where that bound is enforced structurally.
    seg_len: usize,
}

impl TxQueue {
    /// A queue that can hold [`TX_BATCH`] segments of `inner_mtu` bytes each.
    #[must_use]
    pub fn new(inner_mtu: usize) -> Self {
        let seg = OVERLAY_HDR_LEN + inner_mtu;
        Self {
            buf: vec![0u8; TX_BATCH * seg].into_boxed_slice(),
            lens: Vec::with_capacity(TX_BATCH),
            used: 0,
            seg_len: seg,
        }
    }

    /// Segments staged.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.lens.len()
    }

    /// Whether anything is staged.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.lens.is_empty()
    }

    /// Whether another segment would exceed the batch bound.
    #[inline]
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.lens.len() >= TX_BATCH
    }

    /// The staged bytes.
    #[inline]
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.buf[..self.used]
    }

    /// Inner bytes staged, excluding overlay headers.
    #[inline]
    #[must_use]
    pub fn inner_bytes(&self) -> usize {
        self.used - self.lens.len() * OVERLAY_HDR_LEN
    }

    /// Append one segment.
    ///
    /// Returns `false` — without staging anything — when the queue is full or
    /// the frame exceeds the fabric's inner MTU. Both are the caller's cue to flush or
    /// to count a drop; neither can corrupt the buffer.
    ///
    /// Cost: one `copy_from_slice` of the frame, no allocation (`lens` was
    /// reserved at construction and never grows past [`TX_BATCH`]).
    #[inline]
    pub fn push(&mut self, hdr: &[u8; OVERLAY_HDR_LEN], frame: &[u8]) -> bool {
        let len = OVERLAY_HDR_LEN + frame.len();
        if self.is_full() || len > self.seg_len {
            return false;
        }
        let Ok(len16) = u16::try_from(len) else {
            return false;
        };
        self.buf[self.used..self.used + OVERLAY_HDR_LEN].copy_from_slice(hdr);
        self.buf[self.used + OVERLAY_HDR_LEN..self.used + len].copy_from_slice(frame);
        self.used += len;
        self.lens.push(len16);
        true
    }

    /// Forget everything staged. The buffer itself is retained.
    #[inline]
    pub fn clear(&mut self) {
        self.used = 0;
        self.lens.clear();
    }

    /// The GSO spans covering what is staged.
    ///
    /// A span is bounded twice: by `max_segments`, which the kernel reports,
    /// and by [`GSO_MAX_BYTES`], which is what a single segmented write can
    /// carry at all. At full MTU the byte bound binds first — 64 segments of
    /// 1472 B is 94 KiB, and a write that large fails — so leaving it out
    /// would silently lose whole batches.
    ///
    /// Cost: O(segments), no allocation.
    #[must_use]
    pub fn runs(&self, max_segments: usize) -> Runs<'_> {
        Runs {
            lens: &self.lens,
            max: max_segments.max(1),
            max_bytes: GSO_MAX_BYTES,
            next: 0,
            offset: 0,
        }
    }
}

/// Iterator over a queue's GSO spans. See [`TxQueue::runs`].
#[derive(Debug)]
pub struct Runs<'a> {
    lens: &'a [u16],
    max: usize,
    max_bytes: usize,
    next: usize,
    offset: usize,
}

impl Iterator for Runs<'_> {
    type Item = Run;

    fn next(&mut self) -> Option<Run> {
        let &first = self.lens.get(self.next)?;
        let start = self.offset;
        let segment_size = usize::from(first);
        let mut count = 0;
        while count < self.max {
            let Some(&len) = self.lens.get(self.next) else {
                break;
            };
            let len = usize::from(len);
            if count > 0 && self.offset - start + len > self.max_bytes {
                // One segment always fits (it is at most an MTU); a batch may
                // not, so the run ends here and the next one starts.
                break;
            }
            if len > segment_size {
                // A longer segment cannot be part of this run: a GSO batch's
                // segments are all `segment_size` except a shorter last one.
                break;
            }
            self.offset += len;
            self.next += 1;
            count += 1;
            if len < segment_size {
                break;
            }
        }
        Some(Run {
            start,
            end: self.offset,
            count,
            segment_size,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HDR: [u8; OVERLAY_HDR_LEN] = [0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    fn queue(frames: &[usize]) -> TxQueue {
        let mut q = TxQueue::new(1460);
        for len in frames {
            assert!(q.push(&HDR, &vec![0xab; *len]), "staging {len} B");
        }
        q
    }

    #[test]
    fn staging_lays_segments_out_back_to_back() {
        let q = queue(&[4, 4]);
        assert_eq!(q.len(), 2);
        assert_eq!(q.bytes().len(), 2 * (OVERLAY_HDR_LEN + 4));
        assert_eq!(&q.bytes()[..OVERLAY_HDR_LEN], &HDR);
        assert_eq!(&q.bytes()[OVERLAY_HDR_LEN..OVERLAY_HDR_LEN + 4], &[0xab; 4]);
        assert_eq!(q.inner_bytes(), 8);
    }

    #[test]
    fn a_queue_is_bounded_and_reusable() {
        let mut q = queue(&[]);
        for _ in 0..TX_BATCH {
            assert!(q.push(&HDR, &[0u8; 64]));
        }
        assert!(q.is_full());
        assert!(
            !q.push(&HDR, &[0u8; 64]),
            "the bound is structural, not advisory"
        );
        q.clear();
        assert!(q.is_empty() && !q.is_full());
        assert!(q.push(&HDR, &[0u8; 64]));
    }

    #[test]
    fn an_oversized_frame_is_refused_rather_than_truncated() {
        let mut q = TxQueue::new(100);
        assert!(!q.push(&HDR, &[0u8; 101]));
        assert!(q.is_empty());
        assert!(q.push(&HDR, &[0u8; 100]));
    }

    #[test]
    fn uniform_segments_form_one_run() {
        let q = queue(&[100, 100, 100]);
        let runs: Vec<Run> = q.runs(64).collect();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].count, 3);
        assert_eq!(runs[0].segment_size, OVERLAY_HDR_LEN + 100);
        assert_eq!((runs[0].start, runs[0].end), (0, q.bytes().len()));
    }

    #[test]
    fn a_shorter_tail_joins_the_run_and_a_longer_one_starts_a_new_one() {
        let runs: Vec<Run> = queue(&[100, 100, 40]).runs(64).collect();
        assert_eq!(
            runs.len(),
            1,
            "a short final segment is legal GSO: {runs:?}"
        );
        assert_eq!(runs[0].count, 3);

        let runs: Vec<Run> = queue(&[100, 40, 100]).runs(64).collect();
        assert_eq!(runs.len(), 2, "{runs:?}");
        assert_eq!((runs[0].count, runs[1].count), (2, 1));
        assert_eq!(runs[1].start, runs[0].end);
    }

    #[test]
    fn runs_never_exceed_the_gso_segment_limit() {
        let q = queue(&[64; 10]);
        let runs: Vec<Run> = q.runs(4).collect();
        assert_eq!(runs.iter().map(|r| r.count).collect::<Vec<_>>(), [4, 4, 2]);
        assert_eq!(runs.last().map(|r| r.end), Some(q.bytes().len()));
    }

    #[test]
    fn without_gso_every_segment_is_its_own_run() {
        let runs: Vec<Run> = queue(&[64, 64, 64]).runs(1).collect();
        assert_eq!(runs.len(), 3);
        assert!(runs.iter().all(|r| r.count == 1));
    }

    #[test]
    fn runs_are_bounded_by_what_one_segmented_write_can_carry() {
        // 64 full-MTU segments is 94 KiB, past the single-datagram limit.
        let q = queue(&[1460; 64]);
        let runs: Vec<Run> = q.runs(64).collect();
        assert!(runs.len() > 1, "a full-MTU batch must be split: {runs:?}");
        for run in &runs {
            assert!(
                run.end - run.start <= GSO_MAX_BYTES,
                "run of {} B exceeds the limit",
                run.end - run.start
            );
        }
        assert_eq!(runs.iter().map(|r| r.count).sum::<usize>(), q.len());
        assert_eq!(runs.last().map(|r| r.end), Some(q.bytes().len()));
    }

    #[test]
    fn a_single_oversized_segment_still_forms_a_run() {
        // Segments are MTU-bounded, so this can only happen with one segment.
        let q = queue(&[1460]);
        let runs: Vec<Run> = q.runs(64).collect();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].count, 1);
    }

    #[test]
    fn an_empty_queue_has_no_runs() {
        assert_eq!(queue(&[]).runs(64).count(), 0);
    }

    #[test]
    fn runs_partition_the_buffer_exactly() {
        let q = queue(&[10, 10, 5, 20, 20, 1]);
        let runs: Vec<Run> = q.runs(64).collect();
        assert_eq!(runs.first().map(|r| r.start), Some(0));
        assert_eq!(runs.last().map(|r| r.end), Some(q.bytes().len()));
        assert!(runs.windows(2).all(|w| w[0].end == w[1].start), "{runs:?}");
        assert_eq!(runs.iter().map(|r| r.count).sum::<usize>(), q.len());
    }
}
