//! The buffer a pipeline is handed (spec S7.1).
//!
//! A `FrameCtx` is a window onto a receive slot: writable headroom, then the
//! inner Ethernet frame, then whatever capacity remains. The three lengths are
//! private and every operation that could invalidate their relationship is a
//! total function returning `Result`, so "frame longer than its buffer" and
//! "encapsulated past the front of the arena" are states a pipeline cannot
//! construct, not states the harness checks for afterwards.
//!
//! Deviation from the literal spec S7.1 struct, recorded in
//! `docs/deviations.md`: the fields are accessors rather than `pub`, because
//! `data: &mut [u8]` cannot express "there are also bytes *before* this slice",
//! which is exactly what `headroom` promises.

use std::fmt;

/// Headroom the harness guarantees before every frame it presents (spec S7.1).
pub const MIN_HEADROOM: usize = 64;

/// Why a buffer operation was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    /// Encapsulation asked for more bytes than the headroom holds.
    NotEnoughHeadroom {
        /// Bytes requested.
        want: usize,
        /// Bytes available.
        have: usize,
    },
    /// The requested length exceeds the buffer behind the frame.
    NotEnoughCapacity {
        /// Length requested.
        want: usize,
        /// Length available.
        have: usize,
    },
    /// Decapsulation asked to remove more bytes than the frame holds.
    FrameTooShort {
        /// Bytes requested.
        want: usize,
        /// Bytes available.
        have: usize,
    },
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotEnoughHeadroom { want, have } => {
                write!(f, "encap needs {want} B of headroom, {have} B available")
            }
            Self::NotEnoughCapacity { want, have } => {
                write!(f, "frame length {want} exceeds capacity {have}")
            }
            Self::FrameTooShort { want, have } => {
                write!(f, "decap needs {want} B, frame is {have} B")
            }
        }
    }
}

impl std::error::Error for FrameError {}

/// One inner frame, in place, with its harness metadata.
#[derive(Debug)]
pub struct FrameCtx<'a> {
    /// `[0, headroom)` is writable headroom; `[headroom, headroom + len)` is
    /// the frame; the remainder is growth capacity.
    buf: &'a mut [u8],
    headroom: usize,
    len: usize,
    /// The vport the frame arrived on, as the pipeline's ingress port.
    pub ingress_vport: u16,
    /// Harness receive timestamp, `CLOCK_MONOTONIC` microseconds truncated.
    pub rx_ts_us: u32,
}

impl<'a> FrameCtx<'a> {
    /// Present `buf[headroom..headroom + len]` as a frame.
    ///
    /// Returns `None` if that window does not fit in `buf`, which is the only
    /// way the invariant could be broken and the only place it is checked.
    pub fn new(
        buf: &'a mut [u8],
        headroom: usize,
        len: usize,
        ingress_vport: u16,
        rx_ts_us: u32,
    ) -> Option<Self> {
        (headroom.checked_add(len)? <= buf.len()).then_some(Self {
            buf,
            headroom,
            len,
            ingress_vport,
            rx_ts_us,
        })
    }

    /// The frame.
    #[inline]
    #[must_use]
    pub fn frame(&self) -> &[u8] {
        &self.buf[self.headroom..self.headroom + self.len]
    }

    /// The frame, mutably.
    #[inline]
    #[must_use]
    pub fn frame_mut(&mut self) -> &mut [u8] {
        &mut self.buf[self.headroom..self.headroom + self.len]
    }

    /// Current frame length.
    #[inline]
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether the frame is empty. A pipeline that truncates to zero has
    /// effectively dropped it, but the harness still counts the verdict.
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Bytes available in front of the frame for encapsulation.
    #[inline]
    #[must_use]
    pub const fn headroom(&self) -> usize {
        self.headroom
    }

    /// Bytes the frame may grow to without moving.
    #[inline]
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.buf.len() - self.headroom
    }

    /// Set the frame length, keeping the existing prefix.
    pub fn set_len(&mut self, len: usize) -> Result<(), FrameError> {
        if len > self.capacity() {
            return Err(FrameError::NotEnoughCapacity {
                want: len,
                have: self.capacity(),
            });
        }
        self.len = len;
        Ok(())
    }

    /// Shorten the frame; longer requests are a no-op, as for `Vec`.
    pub fn truncate(&mut self, len: usize) {
        self.len = self.len.min(len);
    }

    /// Prepend `n` uninitialized bytes and return them for the caller to fill.
    ///
    /// This is encapsulation: the frame start moves back into the headroom.
    pub fn push_front(&mut self, n: usize) -> Result<&mut [u8], FrameError> {
        if n > self.headroom {
            return Err(FrameError::NotEnoughHeadroom {
                want: n,
                have: self.headroom,
            });
        }
        self.headroom -= n;
        self.len += n;
        Ok(&mut self.buf[self.headroom..self.headroom + n])
    }

    /// Remove `n` bytes from the front of the frame (decapsulation).
    pub fn pop_front(&mut self, n: usize) -> Result<(), FrameError> {
        if n > self.len {
            return Err(FrameError::FrameTooShort {
                want: n,
                have: self.len,
            });
        }
        self.headroom += n;
        self.len -= n;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(buf: &mut [u8]) -> FrameCtx<'_> {
        FrameCtx::new(buf, 64, 4, 0, 0).expect("window fits")
    }

    #[test]
    fn window_must_fit_the_buffer() {
        let mut buf = [0u8; 8];
        assert!(FrameCtx::new(&mut buf, 4, 4, 0, 0).is_some());
        assert!(FrameCtx::new(&mut buf, 4, 5, 0, 0).is_none());
        assert!(
            FrameCtx::new(&mut buf, 0, usize::MAX, 0, 0).is_none(),
            "no overflow wrap"
        );
    }

    #[test]
    fn frame_is_the_window_and_nothing_else() {
        let mut buf = [0u8; 128];
        buf[64..68].copy_from_slice(b"abcd");
        let mut c = ctx(&mut buf);
        assert_eq!(c.frame(), b"abcd");
        c.frame_mut()[0] = b'z';
        assert_eq!(c.frame(), b"zbcd");
        assert_eq!(c.headroom(), 64);
        assert_eq!(c.capacity(), 64);
    }

    #[test]
    fn encap_moves_into_headroom_and_refuses_to_overrun_it() {
        let mut buf = [0u8; 128];
        buf[64..68].copy_from_slice(b"abcd");
        let mut c = ctx(&mut buf);
        c.push_front(2).expect("2 <= 64").copy_from_slice(b"xy");
        assert_eq!(c.frame(), b"xyabcd");
        assert_eq!(c.headroom(), 62);
        assert_eq!(
            c.push_front(63),
            Err(FrameError::NotEnoughHeadroom { want: 63, have: 62 })
        );
    }

    #[test]
    fn decap_removes_from_the_front_and_refuses_to_overrun_the_frame() {
        let mut buf = [0u8; 128];
        buf[64..68].copy_from_slice(b"abcd");
        let mut c = ctx(&mut buf);
        c.pop_front(1).expect("1 <= 4");
        assert_eq!(c.frame(), b"bcd");
        assert_eq!(
            c.pop_front(4),
            Err(FrameError::FrameTooShort { want: 4, have: 3 })
        );
    }

    #[test]
    fn growth_is_bounded_by_capacity() {
        let mut buf = [0u8; 128];
        let mut c = ctx(&mut buf);
        c.set_len(64).expect("fits exactly");
        assert_eq!(
            c.set_len(65),
            Err(FrameError::NotEnoughCapacity { want: 65, have: 64 })
        );
        c.truncate(10);
        assert_eq!(c.len(), 10);
        c.truncate(99);
        assert_eq!(c.len(), 10, "truncate never grows");
    }
}
