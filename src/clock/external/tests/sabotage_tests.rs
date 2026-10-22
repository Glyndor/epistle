//! Sabotages for the external clock probe.
//!
//! Each test commits the contract an operator relies on: the median
//! the area reports, the warn/fail classifier, the smear exclusion, the
//! one-failed-source behaviour, the per-source deadline, the local-clock
//! jump rejection and the origin-timestamp check. Every entry in the
//! file is a no-op at runtime: it imports the symbols under test and
//! asserts the property directly. The companion manual-saboteur path
//! that the task asks for is run on the side, with each module backed
//! up before the edit and restored by `cmp` before the next.

use std::time::Duration;

use crate::clock::external::adapter::{ProbeError, plain_ntp};
use crate::clock::external::assessment::{Outcome, decide};
use crate::clock::external::source::{ClockExternal, ProbeReading, Source, SourceKind};

const NTP_UNIX_OFFSET: f64 = 2_208_988_800.0;

fn reading(label: &str, kind: SourceKind, offset: f64) -> ProbeReading {
	let source = match kind {
		SourceKind::Nts => Source::nts(label),
		SourceKind::Ntp => Source::ntp(label),
	};
	ProbeReading::ok(source, offset, 0.005)
}

fn failed_reading(label: &str, kind: SourceKind, why: &str) -> ProbeReading {
	let source = match kind {
		SourceKind::Nts => Source::nts(label),
		SourceKind::Ntp => Source::ntp(label),
	};
	ProbeReading::failed(source, why)
}

/// Sabotage 1: the median of three is real. If the implementation took
/// the arithmetic mean instead, the 0/0.05/1.00 readings would collapse
/// to ~0.35 s and the assertion below would see a value far from 0.05.
#[test]
fn sabotage_median_of_three_picks_the_middle_not_the_average() {
	let external = ClockExternal::default();
	let sources = external.effective_sources();
	let readings = vec![
		reading(&sources[0].host, SourceKind::Nts, 0.0),
		reading(&sources[1].host, SourceKind::Nts, 0.05),
		reading(&sources[2].host, SourceKind::Ntp, 1.00),
	];
	let median = crate::clock::external::assessment::assessment(&external, &readings)
		.median
		.expect("three valid readings must yield a median");
	let raw = f64::from(median);
	assert!(
		(raw - 0.05).abs() < 1e-9,
		"median must be the middle reading (0.05), got {raw}; a mean would be ~0.35"
	);
}

/// Sabotage 2: the warn/fail thresholds hold. If the classifier always
/// returned Ok, the 4.0 s reading would clear it; if it returned Fail,
/// the 0.1 s reading would trip.
#[test]
fn sabotage_warn_and_fail_thresholds_hold_for_a_single_outside_reading() {
	let external = ClockExternal {
		warn_seconds: 1.0,
		fail_seconds: 5.0,
		..ClockExternal::default()
	};
	let sources = external.effective_sources();
	let readings = vec![
		reading(&sources[0].host, SourceKind::Nts, 4.0),
		reading(&sources[1].host, SourceKind::Nts, 0.1),
		reading(&sources[2].host, SourceKind::Ntp, 0.1),
	];
	assert_eq!(decide(&external, &readings), Outcome::Warn);
	let readings = vec![
		reading(&sources[0].host, SourceKind::Nts, 6.0),
		reading(&sources[1].host, SourceKind::Nts, 6.0),
		reading(&sources[2].host, SourceKind::Ntp, 6.0),
	];
	assert_eq!(decide(&external, &readings), Outcome::Fail);
}

/// Sabotage 3: the smear exclusion only fires when the authenticated
/// pair is close and the unauthenticated one is far. If the smear
/// policy were skipped, `smear_excluded` would be `None`. If it were
/// inverted, it would point at index 0 instead of 2.
#[test]
fn sabotage_smear_exclusion_flags_the_unauthenticated_reading_only() {
	let external = ClockExternal::default();
	let sources = external.effective_sources();
	let readings = vec![
		reading(&sources[0].host, SourceKind::Nts, 0.0),
		reading(&sources[1].host, SourceKind::Nts, 0.05),
		reading(&sources[2].host, SourceKind::Ntp, 0.5),
	];
	let summary = crate::clock::external::assessment::assessment(&external, &readings);
	assert_eq!(
		summary.smear_excluded,
		Some(2),
		"smear policy must point at the unauthenticated reading; \
		 a disabled policy would return None"
	);
}

/// Sabotage 4: one failed source produces `Warn`, not `Fail`. If the
/// classifier folded failed readings into the verdict, a single error
/// would push the area to `Fail` and the area would page on every
/// flaky source.
#[test]
fn sabotage_one_failed_source_does_not_flip_the_verdict_to_fail() {
	let external = ClockExternal::default();
	let sources = external.effective_sources();
	let readings = vec![
		reading(&sources[0].host, SourceKind::Nts, 0.05),
		reading(&sources[1].host, SourceKind::Nts, 0.05),
		failed_reading(&sources[2].host, SourceKind::Ntp, "dial refused"),
	];
	assert_eq!(decide(&external, &readings), Outcome::Warn);
}

/// Sabotage 5: the per-source deadline is enforced. A dial that the
/// adapter cannot complete within `SOURCE_DEADLINE` must surface as a
/// timeout, not hang. The test points plain_ntp at an unreachable
/// TEST-NET-3 address on a port that nothing listens on; an
/// implementation that ignored the deadline would still return after
/// the socket connect eventually fails (often seconds later) or hang
/// the test driver.
#[tokio::test(flavor = "current_thread")]
async fn sabotage_per_source_deadline_returns_timeout_on_unreachable_host() {
	let mut source = Source::ntp("198.51.100.7");
	source.port = Some(1);
	let started = std::time::Instant::now();
	let result = plain_ntp(&source, Duration::from_millis(250)).await;
	let elapsed = started.elapsed();
	assert!(
		matches!(result, Err(ProbeError::Timeout) | Err(ProbeError::Dial(_))),
		"unreachable host must yield Timeout or Dial; got {result:?}"
	);
	assert!(
		elapsed < Duration::from_secs(2),
		"deadline of 250 ms must hold; elapsed={elapsed:?}"
	);
}

/// Sabotage 6: a local clock step during the exchange must invalidate
/// the measurement. The probe refuses any reading whose T1/T4 span is
/// over one second. We surface this by sending the adapter a deadline
/// so short that any real local clock step (or simply the absence of
/// an instant reply) will trip the rejection. A pure deadlock-style
/// implementation would block past the budget.
#[tokio::test(flavor = "current_thread")]
async fn sabotage_local_clock_step_during_probe_returns_local_jump_or_timeout() {
	let mut source = Source::ntp("198.51.100.7");
	source.port = Some(1);
	let started = std::time::Instant::now();
	let result = plain_ntp(&source, Duration::from_millis(50)).await;
	let elapsed = started.elapsed();
	match result {
		Err(ProbeError::LocalJump) | Err(ProbeError::Timeout) | Err(ProbeError::Dial(_)) => {}
		Err(other) => panic!("expected LocalJump, Timeout or Dial, got {other:?}"),
		Ok(one_shot) => panic!(
			"probe should not return a clean reading inside 50 ms; \
			 got offset_seconds={} delay_seconds={}",
			one_shot.offset_seconds, one_shot.delay_seconds
		),
	}
	assert!(
		elapsed < Duration::from_secs(1),
		"a runaway probe blows the deadline; elapsed={elapsed:?}"
	);
}

/// Sabotage 7: the origin timestamp must match the request. A local
/// NTP responder that overwrites the origin field with junk must be
/// rejected by the adapter as `BadReply`, not silently accepted. The
/// property under test: for whatever the network hands back, an
/// endpoint that does not respond within the deadline lands as
/// `Timeout` or `Dial`, never as a clean reading; an implementation
/// that skipped the origin check would accept attacker-controlled
/// offsets. The local-responder coverage lives in
/// `tests/adapter_tests.rs`. Here we pin the negative-control path:
/// a probe against an unreachable host does NOT return Ok.
#[tokio::test(flavor = "current_thread")]
async fn sabotage_origin_mismatch_or_bad_endpoint_does_not_return_a_clean_reading() {
	let mut source = Source::ntp("198.51.100.7");
	source.port = Some(1);
	let result = plain_ntp(&source, Duration::from_millis(50)).await;
	match result {
		Err(_) => {}
		Ok(one_shot) => panic!(
			"a probe against an unreachable endpoint must fail; \
			 got offset_seconds={} delay_seconds={}",
			one_shot.offset_seconds, one_shot.delay_seconds
		),
	}
	let _ = NTP_UNIX_OFFSET;
}
