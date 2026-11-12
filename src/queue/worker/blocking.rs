//! Running synchronous disk work from the worker's async loop.

use tokio::runtime::{Handle, RuntimeFlavor};

/// Run `work`, which reads from disk and may take long on a large spool,
/// without holding the runtime thread the caller is on: on a multi-thread
/// runtime the thread's other tasks move to another one for the duration. A
/// current-thread runtime has nowhere to move them, so `work` runs in place.
pub(super) fn off_the_runtime<T>(work: impl FnOnce() -> T) -> T {
	match Handle::try_current().map(|handle| handle.runtime_flavor()) {
		Ok(RuntimeFlavor::MultiThread) => tokio::task::block_in_place(work),
		_ => work(),
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::sync::Arc;
	use std::sync::atomic::{AtomicBool, Ordering};
	use std::time::{Duration, Instant};

	/// With one runtime thread, a task spawned before the work starts can
	/// only run during it when the work does not hold that thread.
	#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
	async fn other_tasks_run_while_the_work_blocks() {
		// The test body itself runs outside the runtime's one thread, so the
		// work goes into a task that occupies it.
		let seen = tokio::spawn(async {
			let ran = Arc::new(AtomicBool::new(false));
			let flag = Arc::clone(&ran);
			tokio::spawn(async move { flag.store(true, Ordering::SeqCst) });
			off_the_runtime(|| {
				let deadline = Instant::now() + Duration::from_secs(3);
				while Instant::now() < deadline {
					if ran.load(Ordering::SeqCst) {
						return true;
					}
					std::thread::sleep(Duration::from_millis(5));
				}
				false
			})
		})
		.await
		.expect("the task ends");
		assert!(seen, "the spawned task never ran during the blocking work");
	}

	#[tokio::test]
	async fn a_current_thread_runtime_runs_the_work_in_place() {
		assert_eq!(off_the_runtime(|| 7), 7);
	}

	#[test]
	fn outside_a_runtime_the_work_runs_in_place() {
		assert_eq!(off_the_runtime(|| 7), 7);
	}
}
