//! The fast path allocates nothing (spec S6.4, S13.5).
//!
//! Not a soft target: every buffer up4's datapath uses is sized at startup, so
//! a single allocation per frame here means something has started copying into
//! a `Vec` on the way past. The counting allocator is process-wide, so the
//! measured section runs one frame at a time on this thread with the shard
//! thread doing the same work it always does.

use benches::{count_allocations, loopback::Fixture};

/// Batches pushed through the guarded section, and frames per batch.
///
/// Spec S13.5 asks for a million frames over a bench run; a million round trips
/// through a real socket takes minutes, so the *test* uses a number that keeps
/// `cargo test` honest and quick. The property is per-frame — zero allocations,
/// not "few" — so it does not weaken with the count.
const ROUNDS: usize = 320;
const BATCH: usize = 64;
const FRAMES: usize = ROUNDS * BATCH;

#[test]
fn the_datapath_allocates_nothing_per_frame() {
    let mut fixture = Fixture::start("null", |_| {});
    let frame = benches::loopback::frame(1460, [10, 0, 2, 9]);

    // Warm every buffer: the first pass through is where the arenas, the
    // staging queues, and this fixture's own scratch space are allocated.
    assert_eq!(fixture.round_trip(&frame, BATCH), BATCH);

    let (received, allocations) = count_allocations(|| {
        let mut total = 0;
        for _ in 0..ROUNDS {
            total += fixture.round_trip(&frame, BATCH);
        }
        total
    });

    assert_eq!(received, FRAMES, "every frame made it back");
    assert_eq!(
        allocations, 0,
        "{allocations} allocations over {FRAMES} frames; the fast path must allocate nothing"
    );
    assert_eq!(fixture.metrics().harness_drops(), 0);
}
