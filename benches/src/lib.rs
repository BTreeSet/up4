//! Benchmark support: the counting allocator and the loopback fixture.
//!
//! ## Why `unsafe` lives here
//!
//! Spec S1.7 confines `unsafe` to `up4-io`'s syscall plumbing, and the A7 audit
//! greps `crates/` to prove it. This crate is not under `crates/`: it is test
//! scaffolding, it ships in no binary, and a `GlobalAlloc` implementation
//! cannot be written in safe Rust. The audit boundary is unaffected.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, Ordering};

pub mod loopback;

/// Allocations since the process started.
static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);

/// An allocator that counts, and otherwise does nothing of its own.
pub struct Counting;

// SAFETY: every method forwards to `System`, which satisfies the `GlobalAlloc`
// contract, with the same pointers, layouts, and preconditions it was given.
// The counter is a relaxed side effect that touches no allocator state.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// Allocations recorded so far, process-wide.
#[must_use]
pub fn allocations() -> u64 {
    ALLOCATIONS.load(Ordering::SeqCst)
}

/// Run `body` and report how many allocations it caused.
///
/// Process-wide, so the caller must keep other threads quiet for the count to
/// mean anything — which is exactly what the fast-path guard does.
pub fn count_allocations<T>(body: impl FnOnce() -> T) -> (T, u64) {
    let before = allocations();
    let out = body();
    (out, allocations() - before)
}
