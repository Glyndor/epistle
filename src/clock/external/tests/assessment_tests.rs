//! Tests for the median computation, the warn/fail classifier and the
//! leap-second smear policy.

use crate::clock::external::assessment::{Assessment, Outcome, SignedOffset, assessment, decide};
use crate::clock::external::source::{ClockExternal, ProbeReading, Source, SourceKind};

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

#[test]
fn median_of_three_positive_offsets_is_the_middle() {
	let external = ClockExternal::default();
	let readings = vec![
		reading("a", SourceKind::Nts, 0.0),
		reading("b", SourceKind::Nts, 0.01),
		reading("c", SourceKind::Ntp, 0.02),
	];
	let Assessment {
		median, outcome, ..
	} = assessment(&external, &readings);
	assert_eq!(outcome, Outcome::Ok);
	assert_eq!(median, Some(SignedOffset(0.01)));
}

#[test]
fn median_sorts_signed_values_below_zero() {
	let external = ClockExternal::default();
	let readings = vec![
		reading("a", SourceKind::Nts, -0.05),
		reading("b", SourceKind::Nts, -0.04),
		reading("c", SourceKind::Ntp, -0.03),
	];
	let summary = assessment(&external, &readings);
	assert_eq!(summary.median, Some(SignedOffset(-0.04)));
	assert_eq!(summary.outcome, Outcome::Ok);
}

#[test]
fn median_handles_one_negative_one_zero_one_positive() {
	let external = ClockExternal::default();
	let readings = vec![
		reading("a", SourceKind::Nts, -0.1),
		reading("b", SourceKind::Nts, 0.0),
		reading("c", SourceKind::Ntp, 0.1),
	];
	let summary = assessment(&external, &readings);
	assert_eq!(summary.median, Some(SignedOffset(0.0)));
}

#[test]
fn fail_threshold_returns_fail_when_max_exceeds_it() {
	let external = ClockExternal {
		warn_seconds: 1.0,
		fail_seconds: 5.0,
		..ClockExternal::default()
	};
	let readings = vec![
		reading("a", SourceKind::Nts, -8.0),
		reading("b", SourceKind::Nts, 0.0),
		reading("c", SourceKind::Ntp, 0.0),
	];
	assert_eq!(decide(&external, &readings), Outcome::Fail);
}

#[test]
fn warn_threshold_returns_warn_when_max_above_warn_below_fail() {
	let external = ClockExternal {
		warn_seconds: 1.0,
		fail_seconds: 5.0,
		..ClockExternal::default()
	};
	let readings = vec![
		reading("a", SourceKind::Nts, 2.0),
		reading("b", SourceKind::Nts, 0.0),
		reading("c", SourceKind::Ntp, 0.0),
	];
	assert_eq!(decide(&external, &readings), Outcome::Warn);
}

#[test]
fn one_source_failing_does_not_drop_other_below_warn_to_fail() {
	let external = ClockExternal::default();
	let readings = vec![
		reading("a", SourceKind::Nts, 0.1),
		reading("b", SourceKind::Nts, 0.1),
		failed_reading("c", SourceKind::Ntp, "dial"),
	];
	let summary = assessment(&external, &readings);
	assert_eq!(summary.outcome, Outcome::Warn);
	assert!(summary.median.is_none());
}

#[test]
fn all_sources_failing_is_fail() {
	let external = ClockExternal::default();
	let readings = vec![
		failed_reading("a", SourceKind::Nts, "dial"),
		failed_reading("b", SourceKind::Nts, "dial"),
		failed_reading("c", SourceKind::Ntp, "dial"),
	];
	assert_eq!(decide(&external, &readings), Outcome::Fail);
}

#[test]
fn two_valid_one_fail_does_not_violate_threshold_of_three() {
	let external = ClockExternal {
		warn_seconds: 1.0,
		fail_seconds: 5.0,
		..ClockExternal::default()
	};
	let readings = vec![
		reading("a", SourceKind::Nts, 0.1),
		reading("b", SourceKind::Nts, 0.1),
		failed_reading("c", SourceKind::Ntp, "dial"),
	];
	assert_eq!(decide(&external, &readings), Outcome::Warn);
}

#[test]
fn smear_policy_excludes_plain_when_authenticated_pair_close() {
	let external = ClockExternal::default();
	let readings = vec![
		reading("cf", SourceKind::Nts, 0.0),
		reading("netnod", SourceKind::Nts, 0.05),
		reading("google", SourceKind::Ntp, 0.5),
	];
	let summary = assessment(&external, &readings);
	assert_eq!(summary.smear_excluded, Some(2));
}

#[test]
fn smear_policy_does_not_run_when_authenticated_pair_disagrees() {
	let external = ClockExternal::default();
	let readings = vec![
		reading("cf", SourceKind::Nts, 0.0),
		reading("netnod", SourceKind::Nts, 0.5),
		reading("google", SourceKind::Ntp, 0.6),
	];
	let summary = assessment(&external, &readings);
	assert_eq!(summary.smear_excluded, None);
}

#[test]
fn smear_policy_does_not_run_when_authenticated_offsets_within_threshold() {
	let external = ClockExternal::default();
	let readings = vec![
		reading("cf", SourceKind::Nts, 0.0),
		reading("netnod", SourceKind::Nts, 0.05),
		reading("google", SourceKind::Ntp, 0.05),
	];
	let summary = assessment(&external, &readings);
	assert_eq!(summary.smear_excluded, None);
}

#[test]
fn warn_seconds_subsecond_is_preserved_not_clamped_to_defaults() {
	let external = ClockExternal {
		warn_seconds: 0.1,
		fail_seconds: 0.2,
		..ClockExternal::default()
	};
	let readings = vec![
		reading("a", SourceKind::Nts, 0.05),
		reading("b", SourceKind::Nts, 0.05),
		reading("c", SourceKind::Ntp, 0.05),
	];
	let summary = assessment(&external, &readings);
	assert!((summary.warn_seconds - 0.1).abs() < f64::EPSILON);
	assert!((summary.fail_seconds - 0.2).abs() < f64::EPSILON);
	assert_eq!(summary.outcome, Outcome::Ok);
}

#[test]
fn offsets_between_warn_and_fail_threshold_returns_warn() {
	let external = ClockExternal {
		warn_seconds: 0.1,
		fail_seconds: 0.2,
		..ClockExternal::default()
	};
	let readings = vec![
		reading("a", SourceKind::Nts, 0.15),
		reading("b", SourceKind::Nts, 0.05),
		reading("c", SourceKind::Ntp, 0.05),
	];
	let summary = assessment(&external, &readings);
	assert_eq!(summary.outcome, Outcome::Warn);
}
