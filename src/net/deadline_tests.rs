use super::*;

const PREAUTH: Duration = Duration::from_secs(60);
const IDLE: Duration = Duration::from_secs(1800);

#[tokio::test(start_paused = true)]
async fn before_signing_in_every_step_ends_at_the_same_instant() {
	let mut clock = SessionClock::start(PREAUTH, IDLE);
	let end = clock.preauth_until();
	tokio::time::sleep(Duration::from_secs(40)).await;
	assert_eq!(clock.step(false), end);
	assert_eq!(clock.line(false), end);
	clock.line_done();
	assert_eq!(
		clock.line(false),
		end,
		"a new line does not get a new window"
	);
}

#[tokio::test(start_paused = true)]
async fn after_signing_in_a_line_keeps_its_deadline_until_it_is_complete() {
	let mut clock = SessionClock::start(PREAUTH, IDLE);
	let first = clock.line(true);
	tokio::time::sleep(Duration::from_secs(100)).await;
	assert_eq!(clock.line(true), first, "partial reads do not move it");
	clock.line_done();
	assert_eq!(clock.line(true), Instant::now() + IDLE);
}

#[tokio::test(start_paused = true)]
async fn after_signing_in_each_step_gets_a_fresh_window() {
	let clock = SessionClock::start(PREAUTH, IDLE);
	tokio::time::sleep(Duration::from_secs(500)).await;
	assert_eq!(clock.step(true), Instant::now() + IDLE);
}

#[tokio::test(start_paused = true)]
async fn the_preauth_phase_never_outlasts_the_idle_timeout() {
	let clock = SessionClock::start(IDLE, Duration::from_secs(2));
	assert_eq!(
		clock.preauth_until(),
		Instant::now() + Duration::from_secs(2)
	);
}
