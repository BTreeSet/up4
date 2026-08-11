//! The one clock up4 reads.
//!
//! Overlay timestamps must be comparable *between processes* on a host — a
//! pktgen receiver subtracts the timestamp a switch stamped — so this is raw
//! `CLOCK_MONOTONIC` and not `Instant`, whose zero is per-process.
//!
//! Cost: one vDSO call, no syscall on any supported platform. The datapath
//! reads it once per receive batch, not once per frame.

use std::time::{SystemTime, UNIX_EPOCH};

/// Microseconds since an arbitrary fixed point, truncated to 32 bits.
///
/// The truncation is the wire format's (spec S4): the field wraps every ~71.6
/// minutes, which is why it measures deltas and never absolute time.
#[must_use]
pub fn now_us() -> u32 {
    monotonic_us() as u32
}

/// Microseconds since an arbitrary fixed point, untruncated.
#[must_use]
pub fn monotonic_us() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `clock_gettime` writes a `timespec` through the pointer we give
    // it and reads nothing else; `ts` is a live, correctly typed local. The
    // call cannot fail for `CLOCK_MONOTONIC`, which POSIX requires, and a
    // failure would leave `ts` at the zeros it was initialized with rather
    // than uninitialized memory.
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &raw mut ts);
    }
    ts.tv_sec as u64 * 1_000_000 + ts.tv_nsec as u64 / 1_000
}

/// Microseconds since the Unix epoch, for stamping snapshots that humans and
/// other tools will join against. Never used for latency.
#[must_use]
pub fn wall_us() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_micros() as u64)
}

/// Signed difference `later - earlier` in microseconds, correct across the
/// 32-bit wrap of [`now_us`].
#[must_use]
pub const fn delta_us(later: u32, earlier: u32) -> i32 {
    later.wrapping_sub(earlier) as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monotonic_does_not_go_backwards() {
        let a = monotonic_us();
        let b = monotonic_us();
        assert!(b >= a);
    }

    #[test]
    fn wall_clock_is_after_2020() {
        assert!(
            wall_us() > 1_577_836_800_000_000,
            "2020-01-01 in microseconds"
        );
    }

    #[test]
    fn delta_survives_the_wrap() {
        assert_eq!(delta_us(5, 3), 2);
        assert_eq!(delta_us(1, u32::MAX), 2);
        assert_eq!(delta_us(u32::MAX, 1), -2);
    }
}
