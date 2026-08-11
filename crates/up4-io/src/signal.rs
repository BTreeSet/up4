//! Termination signals (spec S12, A6).
//!
//! up4 has no async runtime and no signal handlers on the datapath. Instead the
//! process blocks `SIGTERM`/`SIGINT` in every thread and dedicates one thread
//! to `sigwait`, which turns a signal into an ordinary atomic flag that the
//! shard loops observe between receive batches. The flag is the only thing a
//! "signal handler" here ever touches, so there is no async-signal-safety
//! question to get wrong.

use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
};

/// The signals up4 treats as "shut down cleanly".
const TERMINATING: [libc::c_int; 2] = [libc::SIGTERM, libc::SIGINT];

/// A process-wide "stop" flag.
///
/// Cloneable and cheap to poll: shards check it once per receive batch, the
/// control channel once per accept timeout.
#[derive(Clone, Debug, Default)]
pub struct Stop(Arc<AtomicBool>);

impl Stop {
    /// A flag that is not yet set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether shutdown has been requested.
    #[inline]
    #[must_use]
    pub fn requested(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }

    /// Request shutdown. Idempotent, and callable from anywhere.
    pub fn request(&self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

/// Block the terminating signals in the calling thread.
///
/// **Must be called before any other thread is spawned**: threads inherit the
/// mask, and a signal delivered to a thread that has not blocked it would take
/// the default action and kill the process without a final snapshot.
pub fn block_terminating_signals() -> io::Result<()> {
    let set = terminating_set()?;
    // SAFETY: `set` is a fully initialized `sigset_t` (see `terminating_set`).
    // A null second output pointer means "do not report the old mask", which
    // `pthread_sigmask` explicitly permits.
    let rc =
        unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &raw const set, std::ptr::null_mut()) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(rc))
    }
}

/// Spawn the thread that waits for a terminating signal and sets `stop`.
///
/// The thread exits after the first signal; a second `SIGTERM` therefore takes
/// the default action, which is the escape hatch an operator expects when a
/// graceful shutdown is wedged.
pub fn spawn_watcher(stop: Stop) -> io::Result<JoinHandle<Option<i32>>> {
    let set = terminating_set()?;
    std::thread::Builder::new()
        .name("up4-signal".to_owned())
        .spawn(move || {
            let mut signum: libc::c_int = 0;
            // SAFETY: `set` is initialized, `signum` is a live `c_int`, and
            // `sigwait` writes only through that pointer. The signals are blocked
            // process-wide by `block_terminating_signals`, which is what makes
            // them deliverable here rather than to an arbitrary thread.
            let rc = unsafe { libc::sigwait(&raw const set, &raw mut signum) };
            stop.request();
            (rc == 0).then_some(signum)
        })
}

/// A `sigset_t` containing exactly [`TERMINATING`].
fn terminating_set() -> io::Result<libc::sigset_t> {
    let mut set = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
    // SAFETY: `sigemptyset` initializes the whole `sigset_t` it is given; we
    // only assume it initialized on success, and `sigaddset` then operates on
    // an initialized set with signal numbers libc itself defines.
    let set = unsafe {
        if libc::sigemptyset(set.as_mut_ptr()) != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut set = set.assume_init();
        for sig in TERMINATING {
            if libc::sigaddset(&raw mut set, sig) != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        set
    };
    Ok(set)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_flag_starts_clear_and_latches() {
        let s = Stop::new();
        assert!(!s.requested());
        let clone = s.clone();
        clone.request();
        assert!(s.requested(), "clones share one flag");
        clone.request();
        assert!(s.requested(), "requesting twice is idempotent");
    }

    /// Blocks the signals, sends one, and checks the watcher converts it into
    /// the flag rather than killing the process.
    ///
    /// The signal is directed at the watcher thread specifically. A
    /// process-directed `raise` would be delivered to whichever thread has it
    /// unblocked — under the test harness, one that never called
    /// [`block_terminating_signals`] — and would take the default action.
    #[test]
    fn a_signal_becomes_a_flag() {
        use std::os::unix::thread::JoinHandleExt;

        block_terminating_signals().expect("mask installed");
        let stop = Stop::new();
        let watcher = spawn_watcher(stop.clone()).expect("watcher spawned");
        // SAFETY: the handle is alive (we join it below), so its pthread id is
        // valid; the watcher inherited the blocked mask from this thread, so
        // the signal stays pending for it until `sigwait` collects it.
        let rc = unsafe { libc::pthread_kill(watcher.as_pthread_t(), libc::SIGTERM) };
        assert_eq!(rc, 0, "signal delivered to the watcher thread");
        let signum = watcher.join().expect("watcher thread");
        assert_eq!(signum, Some(libc::SIGTERM));
        assert!(stop.requested());
    }
}
