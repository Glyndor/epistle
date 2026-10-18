//! Waiting without holding up an async runtime.

/// Run `work`, which may wait for a long time (a file lock another holder
/// has), from code that may be on a runtime worker.
///
/// On a multi-thread runtime the worker is handed over for the duration
/// (`block_in_place`), so the other tasks it was going to run, the timers and
/// the sockets go on; on anything else, a plain thread or a current-thread
/// runtime, it just runs. A blocking wait on a worker stalls the listeners
/// that share it: measured, forty `PUTSCRIPT`s of one account moved an `EHLO`
/// on another from 20 ms to 300 to 1100 ms.
pub fn may_block<T>(work: impl FnOnce() -> T) -> T {
	use tokio::runtime::{Handle, RuntimeFlavor};
	match Handle::try_current() {
		Ok(handle) if handle.runtime_flavor() == RuntimeFlavor::MultiThread => {
			tokio::task::block_in_place(work)
		}
		_ => work(),
	}
}
