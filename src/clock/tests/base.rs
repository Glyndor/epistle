use super::*;
use std::time::Duration;

fn at(epoch_secs: u64) -> SystemTime {
	UNIX_EPOCH + Duration::from_secs(epoch_secs)
}

#[test]
fn formats_epoch() {
	assert_eq!(rfc5322(at(0)), "Thu, 01 Jan 1970 00:00:00 +0000");
}

#[test]
fn formats_known_date() {
	// 2026-06-05 12:34:56 UTC.
	assert_eq!(
		rfc5322(at(1_780_662_896)),
		"Fri, 05 Jun 2026 12:34:56 +0000"
	);
}

#[test]
fn formats_leap_day() {
	// 2024-02-29 00:00:00 UTC.
	assert_eq!(
		rfc5322(at(1_709_164_800)),
		"Thu, 29 Feb 2024 00:00:00 +0000"
	);
}

#[test]
fn formats_year_boundary() {
	// 2025-12-31 23:59:59 UTC.
	assert_eq!(
		rfc5322(at(1_767_225_599)),
		"Wed, 31 Dec 2025 23:59:59 +0000"
	);
}

#[test]
fn pre_epoch_clamps_to_epoch() {
	let before = UNIX_EPOCH - Duration::from_secs(86_400);
	assert_eq!(rfc5322(before), "Thu, 01 Jan 1970 00:00:00 +0000");
}

#[test]
fn rfc3339_formats_epoch() {
	assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
}

#[test]
fn rfc3339_formats_known_datetime() {
	// 2026-06-05 12:34:56 UTC.
	assert_eq!(rfc3339(1_780_662_896), "2026-06-05T12:34:56Z");
}

#[test]
fn rfc3339_formats_leap_day() {
	// 2024-02-29 00:00:00 UTC.
	assert_eq!(rfc3339(1_709_164_800), "2024-02-29T00:00:00Z");
}

#[test]
fn rfc3339_formats_year_boundary() {
	// 2025-12-31 23:59:59 UTC.
	assert_eq!(rfc3339(1_767_225_599), "2025-12-31T23:59:59Z");
}

#[test]
fn rfc3339_or_epoch_keeps_the_number_past_the_last_date() {
	assert_eq!(rfc3339_or_epoch(1_780_662_896), "2026-06-05T12:34:56Z");
	assert_eq!(
		rfc3339_or_epoch(LAST_INSTANT),
		"9999-12-31T23:59:59Z",
		"the last date a four-digit year can name is still a date"
	);
	assert_eq!(
		rfc3339_or_epoch(LAST_INSTANT + 1),
		"253402300800",
		"past the last date no year can name it, so the number stays"
	);
}

#[test]
fn drift_threshold_equals_totp_window() {
	// The constant exists to keep the drift counter and the TOTP
	// verifier reading the same number. A future bump to `SKEW_WINDOW`
	// must widen this without a second code site to forget.
	assert_eq!(DRIFT_THRESHOLD_SECONDS, SKEW_WINDOW * STEP_SECONDS);
	assert_eq!(DRIFT_THRESHOLD_SECONDS, 30);
}

#[test]
fn drift_below_threshold_does_not_bump_counter() {
	let metrics = Metrics::new();
	let report = check_drift_with_probe(&metrics, || DriftReport {
		drift_seconds: 5,
		threshold_seconds: DRIFT_THRESHOLD_SECONDS,
	});
	assert_eq!(report.drift_seconds, 5);
	assert_eq!(
		metrics.snapshot().get("clock_drift_exceeded"),
		Some(&0),
		"a 5-second drift sits well inside the TOTP window; the counter \
		 must stay at zero so the alert engine does not page on a value \
		 that does not actually break 2FA"
	);
}

#[test]
fn drift_at_threshold_does_not_bump_counter() {
	// Strictly greater is the rule, so a report that equals the
	// threshold is the boundary case that must still pass.
	let metrics = Metrics::new();
	let _ = check_drift_with_probe(&metrics, || DriftReport {
		drift_seconds: DRIFT_THRESHOLD_SECONDS,
		threshold_seconds: DRIFT_THRESHOLD_SECONDS,
	});
	assert_eq!(metrics.snapshot().get("clock_drift_exceeded"), Some(&0));
}

#[test]
fn drift_above_threshold_bumps_counter_and_renders_in_prometheus() {
	let metrics = Metrics::new();
	let report = check_drift_with_probe(&metrics, || DriftReport {
		drift_seconds: 120,
		threshold_seconds: DRIFT_THRESHOLD_SECONDS,
	});
	assert_eq!(report.drift_seconds, 120);
	assert_eq!(
		metrics.snapshot().get("clock_drift_exceeded"),
		Some(&1),
		"a 120-second drift is twice the TOTP window; every recently \
		 issued 2FA code is one window out of band and the counter \
		 is what the alert engine reads"
	);
	assert!(
		metrics
			.render()
			.contains("mail_clock_drift_exceeded_total 1\n"),
		"{}",
		metrics.render()
	);
}

#[test]
fn live_probe_keeps_counter_at_zero_on_a_healthy_host() {
	// The real probe sleeps for ~PROBE_SLEEP and runs the wall vs.
	// monotonic comparison; on a host with a working clock the
	// observed drift must stay well below the TOTP window.
	let metrics = Metrics::new();
	let report = check_drift(&metrics);
	assert!(
		report.drift_seconds <= DRIFT_THRESHOLD_SECONDS,
		"live probe observed drift_seconds = {}, above threshold = {}; \
		 this means the test machine's clock jumped during the probe",
		report.drift_seconds,
		report.threshold_seconds
	);
	assert_eq!(
		metrics.snapshot().get("clock_drift_exceeded"),
		Some(&0),
		"a healthy probe must leave the counter at zero"
	);
}
