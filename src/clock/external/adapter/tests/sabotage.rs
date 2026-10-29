//! Sabotages for the external clock probe.
//!
//! Each test commits the contract an operator relies on: the median
//! the area reports, the warn/fail classifier, the smear exclusion, the
//! one-failed-source behaviour, the per-source deadline, the local-clock
//! jump rejection and the origin-timestamp check.
//!
//! The three network sabotages run against a local UDP stub on the
//! loopback address of the machine that runs the test. The destination
//! policy of the probe refuses that address by default, so the test asks
//! for it and for the port of the stub explicitly; the production policy
//! is not relaxed for them, and the refusal each sabotage expects is the
//! one the operator reads, not a dial failure.

use std::time::{Duration, Instant, SystemTime};

use crate::clock::external::adapter::{Edge, ProbeError, local_span, plain_ntp_with_policy};
use crate::clock::external::assessment::{Outcome, decide};
use crate::clock::external::source::{ClockExternal, ProbeReading, Source, SourceKind};
use crate::clock::external::tests::udp_stub::{NtpPlan, NtpStub, local_policy, source_for_port};

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

/// Sabotage 5: the per-source deadline is enforced. A source that takes
/// the datagram and never answers must cost the probe the deadline it
/// was given, and the caller must read a timeout: the destination was
/// reached, the server stayed silent, and a dial failure would say
/// something else about what happened. The stub reads the request and
/// keeps it.
#[tokio::test(flavor = "current_thread")]
async fn sabotage_per_source_deadline_expires_on_a_source_that_does_not_answer() {
	let stub = NtpStub::spawn(NtpPlan::Silent);
	let source = source_for_port(stub.port());
	let started = Instant::now();
	let result = tokio::time::timeout(
		Duration::from_secs(5),
		plain_ntp_with_policy(
			&source,
			Duration::from_millis(300),
			local_policy(stub.port()),
		),
	)
	.await
	.expect("the per-source deadline must hold")
	.expect_err("a source that stays silent must not produce a reading");
	assert_eq!(
		result,
		ProbeError::Timeout,
		"a silent source must be a timeout, not {result:?}"
	);
	let elapsed = started.elapsed();
	assert!(
		elapsed >= Duration::from_millis(250),
		"the probe must wait for the deadline it was given; elapsed={elapsed:?}"
	);
	assert!(
		elapsed < Duration::from_secs(2),
		"the probe must not wait past the deadline; elapsed={elapsed:?}"
	);
}

/// Sabotage 6: a local clock step during the exchange invalidates the
/// measurement.
///
/// The exchange is stamped twice, with the wall clock and with the
/// monotonic clock, and a step is what the two disagree about. Over the
/// socket the stub answers later than the span the adapter will vouch
/// for, so the exchange ends in the refusal the operator reads,
/// `LocalJump`, and not in a reading. A step itself cannot be produced
/// over a socket without moving the clock of the host, so it is
/// produced where a step can be made: in the two stamps of the
/// exchange. A wall clock that advanced 300 ms while 1750 ms really
/// passed is a step hidden by the round trip, and the span it leaves is
/// positive and small enough to pass for a measurement.
#[tokio::test(flavor = "current_thread")]
async fn sabotage_local_clock_step_during_the_exchange_is_not_a_measurement() {
	let stub = NtpStub::spawn(NtpPlan::Late(Duration::from_millis(1_200)));
	let source = source_for_port(stub.port());
	let result = tokio::time::timeout(
		Duration::from_secs(5),
		plain_ntp_with_policy(&source, Duration::from_secs(3), local_policy(stub.port())),
	)
	.await
	.expect("the probe must answer before its own deadline")
	.expect_err("an exchange the local span cannot vouch for must not be a reading");
	assert_eq!(
		result,
		ProbeError::LocalJump,
		"a local clock that moved during the exchange must be refused, got {result:?}"
	);

	let sent = Edge {
		wall: SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000),
		monotonic: Instant::now(),
	};
	let received = Edge {
		wall: sent.wall + Duration::from_millis(300),
		monotonic: sent.monotonic + Duration::from_millis(1_750),
	};
	assert!(
		matches!(local_span(sent, received), Err(ProbeError::LocalJump)),
		"a wall clock that advanced 300 ms while 1750 ms really passed is a step, \
		 and the reading must be refused"
	);
}

/// Sabotage 7: the origin timestamp must match the request. A reply that
/// overwrites the origin field with junk must be refused as a bad reply
/// and not read as an offset somebody chose.
#[tokio::test(flavor = "current_thread")]
async fn sabotage_origin_mismatch_is_refused_as_a_bad_reply() {
	let stub = NtpStub::spawn(NtpPlan::WrongOrigin);
	let source = source_for_port(stub.port());
	let result =
		plain_ntp_with_policy(&source, Duration::from_secs(2), local_policy(stub.port())).await;
	match result {
		Err(ProbeError::BadReply(why)) => {
			assert!(
				why.contains("origin"),
				"the refusal must name the origin that did not match: {why}"
			);
		}
		other => panic!("expected the origin mismatch to be refused, got {other:?}"),
	}
}
