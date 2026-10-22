//! The median and the verdict.
//!
//! The verdict uses the largest absolute valid offset. The median and
//! the potential smear reading are diagnostics only; neither removes
//! a valid reading from the verdict.

use crate::clock::external::source::{ClockExternal, ProbeReading, SourceKind};

/// A signed offset (remote minus local), in seconds.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SignedOffset(pub f64);

impl SignedOffset {
	/// Absolute value in seconds.
	pub fn abs_seconds(self) -> f64 {
		self.0.abs()
	}
}

impl From<f64> for SignedOffset {
	fn from(value: f64) -> Self {
		SignedOffset(value)
	}
}

impl From<SignedOffset> for f64 {
	fn from(value: SignedOffset) -> f64 {
		value.0
	}
}

/// The verdict the area reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Outcome {
	/// All three readings are below the warn threshold.
	Ok,
	/// A valid offset reaches the warn threshold, or fewer than three
	/// readings are valid without reaching the fail threshold.
	Warn,
	/// A valid offset reaches the fail threshold, or no readings are valid.
	Fail,
}

/// Two authenticated sources agree to within this many seconds.
const SMEAR_AGREEMENT_SECONDS: f64 = 0.100;

/// A non-authenticated source exceeds the authenticated pair's midpoint by
/// at least this many seconds before it is treated as smeared.
const SMEAR_THRESHOLD_SECONDS: f64 = 0.250;

/// Decide the verdict from the three readings. The classifier respects:
/// - thresholds `0 < warn < fail` (the caller has validated)
/// - missing or failing readings are skipped, never substituted
/// - every valid reading affects the verdict, including a smear candidate
pub fn decide(external: &ClockExternal, readings: &[ProbeReading]) -> Outcome {
	let warn = external.effective_warn();
	let fail = external.effective_fail();
	let valid: Vec<(usize, f64)> = readings
		.iter()
		.enumerate()
		.filter_map(|(index, reading)| {
			if reading.error.is_some() {
				None
			} else {
				Some((index, reading.offset_seconds))
			}
		})
		.collect();
	if valid.is_empty() {
		return Outcome::Fail;
	}
	let max_abs = valid
		.iter()
		.map(|(_, value)| value.abs())
		.fold(0.0f64, f64::max);
	if max_abs >= fail {
		return Outcome::Fail;
	}
	if max_abs >= warn {
		return Outcome::Warn;
	}
	if valid.len() < 3 {
		return Outcome::Warn;
	}
	Outcome::Ok
}

/// Compute the diagnostic median and optional smear candidate. The
/// caller decides the verdict from [`decide`].
pub fn assessment(external: &ClockExternal, readings: &[ProbeReading]) -> Assessment {
	let warn = external.effective_warn();
	let fail = external.effective_fail();
	let valid: Vec<(usize, f64)> = readings
		.iter()
		.enumerate()
		.filter_map(|(index, reading)| {
			if reading.error.is_some() {
				None
			} else {
				Some((index, reading.offset_seconds))
			}
		})
		.collect();
	let median = match valid.len() {
		3 => {
			let mut offsets = [valid[0].1, valid[1].1, valid[2].1];
			offsets.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
			Some(SignedOffset(offsets[1]))
		}
		_ => None,
	};
	let smear_excluded = detect_smear(readings, &valid);
	let outcome = decide(external, readings);
	Assessment {
		outcome,
		median,
		warn_seconds: warn,
		fail_seconds: fail,
		smear_excluded,
	}
}

/// The full assessment the area renders.
#[derive(Debug, Clone, PartialEq)]
pub struct Assessment {
	/// Worst-case verdict across the valid readings.
	pub outcome: Outcome,
	/// Median signed offset (remote minus local), or `None` when fewer than
	/// three readings are valid.
	pub median: Option<SignedOffset>,
	/// Effective warn threshold (seconds, inclusive).
	pub warn_seconds: f64,
	/// Effective fail threshold (seconds, inclusive).
	pub fail_seconds: f64,
	/// Potential smear reading, retained in the verdict despite the field name.
	pub smear_excluded: Option<usize>,
}

/// Identify an unauthenticated smear candidate without excluding it from
/// the verdict, when both authenticated readings agree and the third is
/// more than [`SMEAR_THRESHOLD_SECONDS`] off their midpoint.
fn detect_smear(readings: &[ProbeReading], valid: &[(usize, f64)]) -> Option<usize> {
	if valid.len() != 3 {
		return None;
	}
	let pairs = [
		(valid[0], valid[1], valid[2]),
		(valid[0], valid[2], valid[1]),
		(valid[1], valid[2], valid[0]),
	];
	for (auth_a, auth_b, plain) in pairs {
		if !is_authenticated(readings, auth_a.0) || !is_authenticated(readings, auth_b.0) {
			continue;
		}
		if is_authenticated(readings, plain.0) {
			continue;
		}
		let mid = (auth_a.1 + auth_b.1) / 2.0;
		let gap = (auth_a.1 - auth_b.1).abs();
		if gap <= SMEAR_AGREEMENT_SECONDS && (plain.1 - mid).abs() > SMEAR_THRESHOLD_SECONDS {
			return Some(plain.0);
		}
	}
	None
}

fn is_authenticated(readings: &[ProbeReading], index: usize) -> bool {
	readings
		.get(index)
		.map(|reading| reading.source.kind == SourceKind::Nts)
		.unwrap_or(false)
}

#[cfg(test)]
#[path = "tests/assessment_tests.rs"]
mod tests;
