use std::time::Duration;

use super::*;

const GRACE: Duration = Duration::from_secs(120);

fn window(bytes_per_sec: u64, bytes: u64) -> RateWindow {
	let mut window = DataRate::new(bytes_per_sec, GRACE).start();
	window.bytes = bytes;
	window
}

#[tokio::test(start_paused = true)]
async fn a_client_with_few_bytes_is_judged_when_the_grace_runs_out() {
	let window = window(10_240, 100);
	assert_eq!(window.deadline(), Some(window.start + GRACE));
}

#[tokio::test(start_paused = true)]
async fn the_deadline_is_one_nanosecond_past_what_the_bytes_cover_at_the_floor() {
	let window = window(10_240, 200 * 10_240);
	assert_eq!(
		window.deadline(),
		Some(window.start + Duration::from_secs(200) + Duration::from_nanos(1)),
		"exactly at the floor is not below it"
	);
}

#[tokio::test(start_paused = true)]
async fn a_floor_of_zero_has_no_deadline() {
	assert_eq!(window(0, 0).deadline(), None);
	assert_eq!(window(0, u64::MAX).deadline(), None);
}

#[tokio::test(start_paused = true)]
async fn a_huge_byte_count_does_not_overflow() {
	// u64::MAX bytes at one byte per second: centuries away, never a
	// wrapped deadline in the past.
	let far = window(1, u64::MAX);
	let years = Duration::from_secs(500 * 365 * 86_400);
	assert!(
		far.deadline()
			.is_some_and(|deadline| deadline > far.start + years)
	);
	let window = window(u64::MAX, u64::MAX);
	assert_eq!(window.deadline(), Some(window.start + GRACE));
}

#[tokio::test(start_paused = true)]
async fn the_guard_gives_up_at_the_deadline_and_not_before() {
	let window = window(10_240, 0);
	let started = tokio::time::Instant::now();
	let outcome = window.guard(std::future::pending::<()>()).await;
	assert_eq!(outcome, None);
	assert_eq!(started.elapsed(), GRACE);
	let ready = window.guard(std::future::ready(7)).await;
	assert_eq!(ready, Some(7), "a ready read wins over a passed deadline");
}

#[tokio::test(start_paused = true)]
async fn the_configured_extremes_give_exact_deadlines() {
	// The floor and grace `validate_data_rate` accepts at both ends, with a
	// full 25 MiB counted: 1 B/s puts the deadline 303 days out, and the
	// timer still fires there, not early and not wrapped; 1 GiB/s leaves
	// the grace to decide.
	let full = 25 * 1024 * 1024;
	let mut slowest = DataRate::new(1, Duration::from_secs(3600)).start();
	slowest.bytes = full;
	let due = slowest.start + Duration::from_secs(full) + Duration::from_nanos(1);
	assert_eq!(slowest.deadline(), Some(due));
	assert_eq!(slowest.guard(std::future::pending::<()>()).await, None);
	let late = tokio::time::Instant::now() - due;
	assert!(
		late < Duration::from_millis(2),
		"the far timer fires at its deadline, {late:?} late"
	);
	let mut fastest = DataRate::new(1024 * 1024 * 1024, Duration::from_secs(1)).start();
	fastest.bytes = full;
	assert_eq!(
		fastest.deadline(),
		Some(fastest.start + Duration::from_secs(1))
	);
	fastest.bytes = 0;
	assert_eq!(
		fastest.deadline(),
		Some(fastest.start + Duration::from_secs(1))
	);
}

#[test]
fn the_reply_is_the_exact_line() {
	assert_eq!(
		too_slow().to_string(),
		"421 4.4.2 transfer too slow, closing connection\r\n"
	);
}
