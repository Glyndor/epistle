//! A hostile Mox or Stalwart configuration: what the file says decides how
//! much work the reader does, so a file within the size limit must still be
//! read in time proportional to its size, and what it names must not turn
//! the operator's report into anything but one line of plain text each.

mod mox;
mod prepare;

use std::time::Duration;

/// Longer than any linear read of these files takes, shorter than the
/// quadratic one the cases below would otherwise need.
const WATCHDOG: Duration = Duration::from_secs(20);

/// Run `work` on its own thread under a watchdog: a reader that spends
/// quadratic time fails the test instead of the run.
fn bounded<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> T {
	let (send, receive) = std::sync::mpsc::sync_channel(1);
	let task = std::thread::spawn(move || {
		let _ = send.send(work());
	});
	let result = receive
		.recv_timeout(WATCHDOG)
		.expect("the reader hung or panicked");
	task.join().expect("the reader thread panicked");
	result
}
