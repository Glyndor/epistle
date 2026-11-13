//! The memory watchdog must still stop a worker that buffers without bound.

use super::supervised;

/// A handler that keeps every byte it is given and never stops. The worker
/// grows by 1 MiB every millisecond, so it crosses the ceiling in a fraction
/// of a second; if the watchdog did not kill it the loop would end at 2 GiB
/// and the supervisor would see a pass, which fails the `should_panic`.
#[test]
#[should_panic(expected = "HTTP worker exceeded its anonymous memory ceiling")]
fn a_worker_that_buffers_without_bound_is_killed() {
	if supervised(
		module_path!(),
		"a_worker_that_buffers_without_bound_is_killed",
	) {
		return;
	}
	let mut kept: Vec<Vec<u8>> = Vec::new();
	for _ in 0..2048 {
		kept.push(vec![1u8; 1024 * 1024]);
		std::thread::sleep(std::time::Duration::from_millis(1));
	}
	std::hint::black_box(&kept);
}
