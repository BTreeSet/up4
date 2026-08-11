//! The punt queue (spec S8.3).
//!
//! A bounded ring of preallocated slots between the shard threads (producers)
//! and the control channel (consumer). Depth and slot size are fixed at
//! startup, so a punt storm costs a counter and never memory.
//!
//! The ring is guarded by a `Mutex`, not a lock-free protocol. That is the
//! honest engineering choice here: punting is a control-plane path by
//! definition, the critical section is one bounded `copy_from_slice`, and a
//! lock-free ring in this crate would need `unsafe` for something that is not
//! syscall plumbing (spec S1.7).

use std::sync::Mutex;

/// Ring depth (spec S8.3).
pub const PUNT_DEPTH: usize = 1024;

/// One punted frame, handed to the control channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PuntFrame {
    /// Vport the frame arrived on.
    pub ingress_vport: u16,
    /// Harness receive timestamp (spec S7.1).
    pub rx_ts_us: u32,
    /// The inner Ethernet frame, overlay header already stripped.
    pub bytes: Vec<u8>,
}

/// A preallocated slot; `len` says how much of `buf` is live.
#[derive(Debug)]
struct Slot {
    ingress_vport: u16,
    rx_ts_us: u32,
    len: usize,
    buf: Box<[u8]>,
}

#[derive(Debug)]
struct Ring {
    slots: Box<[Slot]>,
    head: usize,
    len: usize,
}

/// The bounded punt queue.
#[derive(Debug)]
pub struct PuntQueue {
    ring: Mutex<Ring>,
}

impl PuntQueue {
    /// A queue of [`PUNT_DEPTH`] slots, each able to hold `inner_mtu` bytes.
    #[must_use]
    pub fn new(inner_mtu: usize) -> Self {
        Self::with_depth(PUNT_DEPTH, inner_mtu)
    }

    /// A queue with an explicit depth. Tests use this; production uses
    /// [`PuntQueue::new`], because the depth is part of the spec.
    #[must_use]
    pub fn with_depth(depth: usize, inner_mtu: usize) -> Self {
        let slots = (0..depth.max(1))
            .map(|_| Slot {
                ingress_vport: 0,
                rx_ts_us: 0,
                len: 0,
                buf: vec![0u8; inner_mtu].into_boxed_slice(),
            })
            .collect();
        Self {
            ring: Mutex::new(Ring {
                slots,
                head: 0,
                len: 0,
            }),
        }
    }

    /// Enqueue a frame. `false` means the ring was full and the caller must
    /// count `punt_overflow_drop`.
    ///
    /// Cost: one lock and one copy of at most the inner MTU.
    pub fn push(&self, frame: &[u8], ingress_vport: u16, rx_ts_us: u32) -> bool {
        let mut ring = self.lock();
        if ring.len == ring.slots.len() {
            return false;
        }
        let at = (ring.head + ring.len) % ring.slots.len();
        let slot = &mut ring.slots[at];
        // The harness rejects oversize frames before dispatch, so this
        // saturation is unreachable; truncating beats refusing a frame the
        // operator asked to see.
        let len = frame.len().min(slot.buf.len());
        slot.buf[..len].copy_from_slice(&frame[..len]);
        slot.len = len;
        slot.ingress_vport = ingress_vport;
        slot.rx_ts_us = rx_ts_us;
        ring.len += 1;
        true
    }

    /// Dequeue up to `max` frames, oldest first.
    pub fn drain(&self, max: usize) -> Vec<PuntFrame> {
        let mut ring = self.lock();
        let take = max.min(ring.len);
        let mut out = Vec::with_capacity(take);
        for _ in 0..take {
            let head = ring.head;
            let slot = &ring.slots[head];
            out.push(PuntFrame {
                ingress_vport: slot.ingress_vport,
                rx_ts_us: slot.rx_ts_us,
                bytes: slot.buf[..slot.len].to_vec(),
            });
            ring.head = (head + 1) % ring.slots.len();
            ring.len -= 1;
        }
        out
    }

    /// Frames waiting.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lock().len
    }

    /// Whether nothing is waiting.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Slots in the ring.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.lock().slots.len()
    }

    /// A poisoned punt lock means a producer panicked mid-copy. The ring's
    /// bookkeeping is updated only after the copy completes, so recovering
    /// costs at most one stale slot's contents and keeps the switch alive.
    fn lock(&self) -> std::sync::MutexGuard<'_, Ring> {
        self.ring.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn frames_come_back_in_order_with_their_metadata() {
        let q = PuntQueue::with_depth(4, 64);
        assert!(q.push(b"one", 3, 111));
        assert!(q.push(b"two", 4, 222));
        assert_eq!(q.len(), 2);
        assert_eq!(
            q.drain(10),
            vec![
                PuntFrame {
                    ingress_vport: 3,
                    rx_ts_us: 111,
                    bytes: b"one".to_vec()
                },
                PuntFrame {
                    ingress_vport: 4,
                    rx_ts_us: 222,
                    bytes: b"two".to_vec()
                },
            ]
        );
        assert!(q.is_empty());
    }

    #[test]
    fn a_full_ring_refuses_rather_than_growing() {
        let q = PuntQueue::with_depth(2, 64);
        assert!(q.push(b"a", 0, 0));
        assert!(q.push(b"b", 0, 0));
        assert!(
            !q.push(b"c", 0, 0),
            "the third push is the overflow counter's job"
        );
        assert_eq!(q.len(), 2);
        assert_eq!(q.capacity(), 2);
    }

    #[test]
    fn draining_frees_slots_and_the_ring_wraps() {
        let q = PuntQueue::with_depth(2, 64);
        for round in 0..5u8 {
            assert!(q.push(&[round], 0, 0));
            assert!(q.push(&[round, round], 0, 0));
            let got = q.drain(2);
            assert_eq!(got.len(), 2);
            assert_eq!(got[0].bytes, vec![round]);
            assert_eq!(got[1].bytes, vec![round, round]);
        }
    }

    #[test]
    fn partial_drains_leave_the_rest_in_order() {
        let q = PuntQueue::with_depth(4, 64);
        for i in 0..4u8 {
            assert!(q.push(&[i], 0, 0));
        }
        assert_eq!(
            q.drain(2).iter().map(|f| f.bytes[0]).collect::<Vec<_>>(),
            [0, 1]
        );
        assert_eq!(
            q.drain(99).iter().map(|f| f.bytes[0]).collect::<Vec<_>>(),
            [2, 3]
        );
        assert_eq!(q.drain(1), vec![]);
    }

    #[test]
    fn a_frame_larger_than_a_slot_is_truncated_not_refused() {
        let q = PuntQueue::with_depth(1, 4);
        assert!(q.push(b"abcdefgh", 0, 0));
        assert_eq!(q.drain(1)[0].bytes, b"abcd".to_vec());
    }

    #[test]
    fn producers_and_the_consumer_may_run_concurrently() {
        const PRODUCERS: u16 = 4;
        const PUSHES: usize = 1000;
        const DEPTH: usize = 8;

        let q = Arc::new(PuntQueue::with_depth(DEPTH, 64));
        // The consumer needs an exit condition that some invariant actually
        // implies. "Drain until N frames arrive" is not one: the ring is
        // bounded and lossy on purpose, so the frames it accepts are
        // `DEPTH + already drained`, never a function of how many were
        // offered. Once the producers stop, `drain` returns empty forever and
        // a count-based guard spins for good. Producers still running is a
        // fact this test owns, and it becomes false in bounded time.
        let live = Arc::new(AtomicUsize::new(PRODUCERS as usize));

        let producers: Vec<_> = (0..PRODUCERS)
            .map(|id| {
                let (q, live) = (Arc::clone(&q), Arc::clone(&live));
                std::thread::spawn(move || {
                    let accepted = (0..PUSHES).fold(0, |n, _| n + usize::from(q.push(b"x", id, 0)));
                    live.fetch_sub(1, Ordering::Release);
                    accepted
                })
            })
            .collect();

        let mut drained = 0;
        while live.load(Ordering::Acquire) > 0 {
            drained += q.drain(DEPTH).len();
            std::thread::yield_now();
        }
        // Reading zero live producers happens-after every producer's last
        // push, so nothing can arrive behind this final sweep.
        drained += q.drain(usize::MAX).len();

        let accepted: usize = producers
            .into_iter()
            .map(|h| h.join().expect("producer"))
            .sum();
        assert_eq!(accepted, drained, "every accepted frame is accounted for");
        assert!(
            (DEPTH..=PRODUCERS as usize * PUSHES).contains(&accepted),
            "a refused push proves DEPTH resident frames were accepted, and \
             nothing is invented: got {accepted}"
        );
        assert!(q.is_empty(), "the final sweep leaves nothing behind");
    }
}
