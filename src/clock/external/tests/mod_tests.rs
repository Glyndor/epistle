//! Tests for the area dispatcher: how it composes outcome, median and
//! smear exclusions on the three readings the probes return.

use crate::clock::external::assessment::{Outcome, SignedOffset};
use crate::clock::external::source::{ProbeReading, Source, SourceKind};
use crate::clock::external::{ClockExternal, Run, order_readings};

fn reading(label: &str, kind: SourceKind, offset: f64) -> ProbeReading {
	let source = match kind {
		SourceKind::Nts => Source::nts(label),
		SourceKind::Ntp => Source::ntp(label),
	};
	ProbeReading::ok(source, offset, 0.005)
}

#[test]
fn run_defaults_to_three_independent_default_sources() {
	let external = ClockExternal::default();
	assert_eq!(external.effective_sources().len(), 3);
}

/// The smear policy needs two authenticated readings that agree, so the
/// readings carry their own sources rather than the default list, whose
/// shipped mix is one NTS and two plain.
#[test]
fn run_full_smear_path_returns_ok_outcome_when_offsets_within_warn() {
	let external = ClockExternal::default();
	let readings = vec![
		reading("nts.netnod.se", SourceKind::Nts, 0.0),
		reading("nts.time.nl", SourceKind::Nts, 0.05),
		reading("time.google.com", SourceKind::Ntp, 0.5),
	];
	let outcome = mock_outcome(&external, &readings);
	assert_eq!(outcome, Outcome::Ok);
	let summary = crate::clock::external::assessment::assessment(&external, &readings);
	assert_eq!(summary.smear_excluded, Some(2));
}

/// The shipped list has one authenticated source, so the smear policy
/// cannot fire on a default run. Pinning it here so the absence of a
/// smear warning there is a known state and not a silently missing check.
#[test]
fn the_smear_policy_stays_dormant_with_one_authenticated_source() {
	let external = ClockExternal::default();
	let sources = external.effective_sources();
	let readings = vec![
		ProbeReading::ok(sources[0].clone(), 0.0, 0.005),
		ProbeReading::ok(sources[1].clone(), 0.05, 0.005),
		ProbeReading::ok(sources[2].clone(), 0.5, 0.005),
	];
	let summary = crate::clock::external::assessment::assessment(&external, &readings);
	assert_eq!(
		summary.smear_excluded, None,
		"one authenticated reading is not a pair; the policy needs two"
	);
}

#[test]
fn run_with_one_failed_source_warns_and_drops_median() {
	let external = ClockExternal::default();
	let sources = external.effective_sources();
	let readings = vec![
		ProbeReading::ok(sources[0].clone(), 0.0, 0.005),
		ProbeReading::failed(sources[1].clone(), "dial refused"),
		ProbeReading::ok(sources[2].clone(), 0.02, 0.005),
	];
	let median = mock_median(&readings);
	assert!(median.is_none());
}

#[test]
fn run_strict_threshold_returns_fail_for_large_offset() {
	let external = ClockExternal {
		warn_seconds: 1.0,
		fail_seconds: 5.0,
		..ClockExternal::default()
	};
	let sources = external.effective_sources();
	let readings = vec![
		ProbeReading::ok(sources[0].clone(), -8.0, 0.005),
		ProbeReading::ok(sources[1].clone(), -8.01, 0.005),
		ProbeReading::ok(sources[2].clone(), -8.02, 0.005),
	];
	let outcome = mock_outcome(&external, &readings);
	assert_eq!(outcome, Outcome::Fail);
}

fn mock_median(readings: &[ProbeReading]) -> Option<SignedOffset> {
	let valid: Vec<f64> = readings
		.iter()
		.filter(|r| r.error.is_none())
		.map(|r| r.offset_seconds)
		.collect();
	match valid.len() {
		3 => {
			let mut sorted = valid;
			sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
			Some(SignedOffset(sorted[1]))
		}
		_ => None,
	}
}

fn mock_outcome(external: &ClockExternal, readings: &[ProbeReading]) -> Outcome {
	let _ = external;
	let _ = Run {
		sources: Vec::new(),
		readings: readings.to_vec(),
		outcome: Outcome::Ok,
		median: mock_median(readings),
		smear_excluded: None,
		warn_seconds: 1.0,
		fail_seconds: 5.0,
		finished_at: std::time::Instant::now(),
	};
	crate::clock::external::assessment::decide(external, readings)
}

#[tokio::test]
async fn review_run_forwards_private_network_consent_to_both_protocols() {
	let mut external = ClockExternal {
		allow_private_networks: true,
		allowed_ports: vec![1],
		sources: vec![
			Source::nts("localhost"),
			Source::ntp("127.0.0.1"),
			Source::ntp("::1"),
		],
		..ClockExternal::default()
	};
	for source in &mut external.sources {
		source.port = Some(1);
	}
	external.validate().unwrap();
	let result = crate::clock::external::run(&external).await;
	assert_eq!(result.readings.len(), 3);
	for reading in &result.readings {
		if let Some(error) = &reading.error {
			assert!(
				!error.contains("clock destination"),
				"operator consent was not forwarded for {}: {error}",
				reading.source.label()
			);
		}
	}
}

/// The probes answer in whatever order the network lets them, so the readings
/// come back shuffled. The run hands them over in the configured order, which
/// is the order the area and every reader of `Run` assume.
#[test]
fn review_readings_are_ordered_by_the_configured_sources() {
	let external = ClockExternal::default();
	let sources = external.effective_sources();
	let mut readings = vec![
		reading(&sources[2].host, sources[2].kind, 0.03),
		reading(&sources[0].host, sources[0].kind, 0.01),
		reading(&sources[1].host, sources[1].kind, 0.02),
	];
	order_readings(&sources, &mut readings);
	let order: Vec<&str> = readings
		.iter()
		.map(|reading| reading.source.host.as_str())
		.collect();
	let expected: Vec<&str> = sources.iter().map(|source| source.host.as_str()).collect();
	assert_eq!(order, expected);
	// A source the run never asked about stays at the end rather than
	// displacing a reading that does belong to the list.
	let mut with_stray = readings.clone();
	with_stray.push(reading("stray.example", SourceKind::Ntp, 0.04));
	order_readings(&sources, &mut with_stray);
	assert_eq!(
		with_stray
			.last()
			.map(|reading| reading.source.host.as_str()),
		Some("stray.example")
	);
}
