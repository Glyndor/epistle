//! RFC 5322 date-time formatting from system time, without external crates.
//!
//! Mail trace headers want `Day, DD Mon YYYY HH:MM:SS +0000`. The server
//! always stamps UTC, so no zone database is needed.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::metrics::Metrics;
use crate::totp::{SKEW_WINDOW, STEP_SECONDS};

const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const MONTHS: [&str; 12] = [
	"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Format a timestamp as an RFC 5322 date-time in UTC.
pub fn rfc5322(time: SystemTime) -> String {
	let secs = time
		.duration_since(UNIX_EPOCH)
		.map(|duration| duration.as_secs() as i64)
		.unwrap_or(0);

	let days_since_epoch = secs.div_euclid(86_400);
	let seconds_of_day = secs.rem_euclid(86_400);

	let (year, month, day) = civil_from_days(days_since_epoch);
	// 1970-01-01 was a Thursday (weekday index 4).
	let weekday = (days_since_epoch + 4).rem_euclid(7) as usize;

	format!(
		"{}, {:02} {} {} {:02}:{:02}:{:02} +0000",
		DAYS[weekday],
		day,
		MONTHS[(month - 1) as usize],
		year,
		seconds_of_day / 3600,
		(seconds_of_day % 3600) / 60,
		seconds_of_day % 60,
	)
}

/// Days-since-epoch to (year, month, day), Howard Hinnant's algorithm.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
	let z = days + 719_468;
	let era = z.div_euclid(146_097);
	let doe = z.rem_euclid(146_097);
	let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
	let year = yoe + era * 400;
	let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
	let mp = (5 * doy + 2) / 153;
	let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
	let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
	(if month <= 2 { year + 1 } else { year }, month, day)
}

/// Format a Unix timestamp (seconds) as an RFC 3339 / ISO 8601 date-time in
/// UTC: `YYYY-MM-DDTHH:MM:SSZ`. Used for TLS-RPT report `date-range` values
/// (RFC 8460 §4.3), which require ISO 8601 rather than the RFC 5322 form.
pub fn rfc3339(unix_secs: u64) -> String {
	let secs = unix_secs as i64;
	let days_since_epoch = secs.div_euclid(86_400);
	let seconds_of_day = secs.rem_euclid(86_400);
	let (year, month, day) = civil_from_days(days_since_epoch);
	format!(
		"{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
		year,
		month,
		day,
		seconds_of_day / 3600,
		(seconds_of_day % 3600) / 60,
		seconds_of_day % 60
	)
}

/// The drift threshold above which a startup probe fires the
/// `clock_drift_exceeded` counter and a one-shot `warn!`. Tied to the
/// TOTP acceptance window: a clock that jumps by more than ±`SKEW_WINDOW`
/// steps of `STEP_SECONDS` (the configured ±30 s in [`crate::totp`])
/// silently rejects every recently-issued second factor, because every
/// account's 30-second slot is now one slot ahead or behind the user's
/// authenticator app. DKIM signature timestamps ride on the same clock
/// and tolerate a similar order of magnitude, so the same threshold
/// covers both signals this server emits. Linking the two means a
/// future bump to `SKEW_WINDOW` automatically widens the drift window
/// the operator gets warned about.
pub const DRIFT_THRESHOLD_SECONDS: u64 = SKEW_WINDOW * STEP_SECONDS;

/// How long the probe sleeps between two clock samples. One tenth of a
/// second is short enough not to delay startup and long enough to
/// register on a sub-millisecond clock; making it shorter would not
/// sharpen the measurement.
const PROBE_SLEEP: Duration = Duration::from_millis(100);

/// Outcome of one startup drift probe. The threshold is repeated on the
/// report so log readers see the number the counter compares against
/// without having to look it up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DriftReport {
	/// Largest absolute drift between wall-clock and monotonic time
	/// observed across the probe, in whole seconds.
	pub drift_seconds: u64,
	/// The threshold the report was compared against. Equal to
	/// [`DRIFT_THRESHOLD_SECONDS`] for every call out of [`check_drift`].
	pub threshold_seconds: u64,
}

/// Probe the system clock at startup and bump `metrics.clock_drift_exceeded`
/// when the observed drift exceeds [`DRIFT_THRESHOLD_SECONDS`]. Returns
/// the report so the caller (and tests) can read the raw measurement.
///
/// The detection is entirely local: the server carries no external
/// reference for UTC. A clock that is uniformly two minutes slow looks
/// identical to one that is on time, because nothing on the host knows
/// "real" UTC. What we *can* catch is a clock that jumps — an NTP step
/// adjustment, an operator running `date -s` mid-startup, a VM clock
/// that paused and resumed — because those are the same jumps that
/// break TOTP and DKIM: the wall clock disagrees with itself across a
/// short window, and a verifier of the timestamps we emit would see
/// the same disagreement.
///
/// The probe samples `SystemTime` twice with a `PROBE_SLEEP` gap and
/// compares the wall-clock elapsed time against the monotonic elapsed
/// time from [`Instant`]. The two come from the same source on a
/// healthy host, so any disagreement of more than `DRIFT_THRESHOLD_SECONDS`
/// is the same adjustment that just pushed every TOTP step out of band.
pub fn check_drift(metrics: &Metrics) -> DriftReport {
	check_drift_with_probe(metrics, probe)
}

/// Same as [`check_drift`] but with a caller-supplied probe. Used by the
/// tests to drive the threshold logic without sleeping for [`PROBE_SLEEP`].
fn check_drift_with_probe(metrics: &Metrics, probe: fn() -> DriftReport) -> DriftReport {
	let report = probe();
	if report.drift_seconds > report.threshold_seconds {
		metrics.clock_drift_exceeded();
		tracing::warn!(
			drift_seconds = report.drift_seconds,
			threshold_seconds = report.threshold_seconds,
			"system clock drift exceeds the TOTP acceptance window; \
			 two-factor authentication may be rejected for every account \
			 and DKIM signatures may fall outside the receiver's validity \
			 window. Time synchronisation is the operator's responsibility \
			 (chrony, systemd-timesyncd, ntpd)."
		);
	}
	report
}

/// The pure probe: sample twice and report. Pulled out of [`check_drift`]
/// so tests can drive it without going through `Metrics`.
fn probe() -> DriftReport {
	let t0 = SystemTime::now();
	let m0 = Instant::now();
	std::thread::sleep(PROBE_SLEEP);
	let t1 = SystemTime::now();
	let m1 = Instant::now();
	// Wall-clock elapsed, signed: positive when `t1 >= t0`, negative when
	// the clock went backwards (a clock step-down looks like this to
	// `duration_since`, which saturates to zero on the wrong side of a
	// backwards jump). The signed wall elapsed minus the always-positive
	// monotonic elapsed is the actual drift.
	let wall_secs_signed = match t1.duration_since(t0) {
		Ok(d) => d.as_secs_f64(),
		Err(_) => -t0
			.duration_since(t1)
			.map(|d| d.as_secs_f64())
			.unwrap_or(0.0),
	};
	let mono_secs = m1.duration_since(m0).as_secs_f64();
	let drift = (wall_secs_signed - mono_secs).abs();
	DriftReport {
		drift_seconds: drift.round() as u64,
		threshold_seconds: DRIFT_THRESHOLD_SECONDS,
	}
}

#[cfg(test)]
mod tests {
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
}
