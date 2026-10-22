//! Tests for the clock area: rendering the host probe verdict; the
//! external probe path exercises its own internal tests.

use std::time::Instant;

use super::{HostClock, NoRun, check, compose, compose_joined};
use crate::cli::status::report::{AreaReport, Item, Level};
use crate::clock::external::{ClockExternal, Outcome, ProbeReading, Run, SignedOffset, Source};

#[test]
fn a_synchronised_host_renders_ok_without_fix_suggestions() {
	let report = compose(HostClock::Synced, None, &Default::default(), None);
	assert_eq!(report.status, Level::Ok, "{report:?}");
	assert_eq!(report.detail, "external clock probe not run");
	assert!(
		report.items.iter().all(|item| item.status == Level::Ok),
		"{report:?}"
	);
}

#[test]
fn an_unsynchronised_host_warns_and_names_the_fixes() {
	let report = compose(HostClock::Unsynced, None, &Default::default(), None);
	assert_eq!(report.status, Level::Warn, "{report:?}");
	let fix = report.items.iter().find(|item| item.name == "to fix");
	assert!(fix.is_some(), "{report:?}");
}

#[test]
fn a_clock_that_cannot_be_read_warns_with_the_reason_instead_of_guessing() {
	let report = compose(
		HostClock::Unknown("no adjtimex".to_string()),
		None,
		&Default::default(),
		None,
	);
	assert_eq!(report.status, Level::Warn, "{report:?}");
	let host = report
		.items
		.iter()
		.find(|item| item.name == "host synchronisation")
		.expect("host item");
	assert!(host.detail.contains("no adjtimex"), "{host:?}");
}

/// A finished run over `sources`, with every source answering.
fn run_over(sources: Vec<Source>) -> Run {
	let readings: Vec<ProbeReading> = sources
		.iter()
		.map(|source| ProbeReading::ok(source.clone(), 0.01, 0.2))
		.collect();
	Run {
		sources,
		readings,
		outcome: Outcome::Ok,
		median: Some(SignedOffset(0.01)),
		smear_excluded: None,
		warn_seconds: 1.0,
		fail_seconds: 5.0,
		finished_at: Instant::now(),
	}
}

fn item<'a>(report: &'a AreaReport, name: &str) -> &'a Item {
	let found = report.items.iter().find(|item| item.name == name);
	assert!(found.is_some(), "the area must report {name}: {report:?}");
	found.unwrap()
}

/// The default list carries one authenticated source, so the area must say
/// so instead of rendering three offsets that read as equally trusted.
#[test]
fn the_area_names_how_many_sources_were_authenticated() {
	let external = ClockExternal::default();
	let run = run_over(external.effective_sources());
	let report = compose(HostClock::Synced, Some(&run), &external, None);
	let note = item(&report, "authentication");
	assert_eq!(note.status, Level::Ok, "{note:?}");
	assert!(
		note.detail
			.contains("1 of 3 sources authenticated over NTS"),
		"{note:?}"
	);
	assert!(note.detail.contains("nts.netnod.se"), "{note:?}");
	assert!(
		note.detail.contains("plain NTPv4"),
		"the line must name what the other two are; {note:?}"
	);
}

/// A list with no NTS entry cannot produce an authenticated reading at all,
/// and the area must warn rather than present the offsets as ordinary.
#[test]
fn a_run_without_an_authenticated_source_warns_instead_of_claiming_authentication() {
	let external = Default::default();
	let sources = vec![
		Source::ntp("time.cloudflare.com"),
		Source::ntp("time.google.com"),
		Source::ntp("pool.ntp.example"),
	];
	let run = run_over(sources);
	let report = compose(HostClock::Synced, Some(&run), &external, None);
	let note = item(&report, "authentication");
	assert_eq!(note.status, Level::Warn, "{note:?}");
	assert!(
		note.detail
			.contains("no source in this run is NTS-authenticated"),
		"{note:?}"
	);
}

/// The default list names one NTS source whether or not it answered, and a
/// source that never completed its key exchange authenticated nothing. Counting
/// the configuration instead of the reading reported an authentication that
/// never happened next to a failed source.
#[test]
fn a_configured_nts_source_that_never_answered_is_not_counted_as_authenticated() {
	let external = ClockExternal::default();
	let run = assessed_run(&[None, None, None]);
	let report = compose(HostClock::Synced, Some(&run), &external, None);
	let note = item(&report, "authentication");
	assert_eq!(note.status, Level::Warn, "{note:?}");
	assert!(
		!note.detail.contains("sources authenticated over NTS"),
		"nothing came over NTS, so the line must not say it did: {note:?}"
	);
	assert!(
		note.detail.contains("configured for NTS"),
		"the line must still name what the operator configured: {note:?}"
	);
	assert!(note.detail.contains("nts.netnod.se"), "{note:?}");
}

/// Two plain sources answering and the NTS source failing is the case a
/// configured count gets wrong: the offsets are real, they are plain NTPv4,
/// and the authentication line must not stand in for them.
#[test]
fn nts_configured_but_failed_leaves_the_other_offsets_plain() {
	let external = ClockExternal::default();
	let run = assessed_run(&[Some(0.01), None, Some(0.01)]);
	let report = compose(HostClock::Synced, Some(&run), &external, None);
	let note = item(&report, "authentication");
	assert_eq!(note.status, Level::Warn, "{note:?}");
	assert!(
		!note.detail.contains("sources authenticated over NTS"),
		"{note:?}"
	);
	assert!(
		note.detail.contains("returned no authenticated reading"),
		"{note:?}"
	);
}

/// A probe task that failed on its own is not a probe that was never asked, and
/// it is not the operator switching it off either. Both absences were rendered
/// as a healthy area with no warning at all, so the area names the cause.
#[tokio::test(flavor = "current_thread")]
async fn a_probe_task_that_fails_is_named_instead_of_reading_as_no_probe() {
	let joined = tokio::task::spawn_blocking(|| panic!("the probe thread died")).await;
	let error = joined.expect_err("the task panicked, so the join carries the reason");
	let report = compose_joined(HostClock::Synced, Err(error), &Default::default());
	assert_eq!(report.status, Level::Warn, "{report:?}");
	let note = item(&report, "external probe");
	assert!(note.detail.contains("the probe task failed"), "{note:?}");
	assert!(
		note.detail.contains("the probe thread died"),
		"the cause tokio reports has to reach the operator: {note:?}"
	);
	assert_eq!(report.detail, "external clock probe not run", "{report:?}");
}

/// No runtime to await the probe on is a third absence: not a failure of the
/// thread and not the voluntary switch-off, and it is told apart by name.
#[test]
fn a_probe_task_without_a_runtime_is_named_as_such() {
	let report = compose_joined(
		HostClock::Synced,
		Ok(Err(NoRun::Runtime)),
		&Default::default(),
	);
	assert_eq!(report.status, Level::Warn, "{report:?}");
	let note = item(&report, "external probe");
	assert!(note.detail.contains("no async runtime"), "{note:?}");
}

/// A run that came back is rendered as it was, with no failure finding bolted on
/// top of it.
#[test]
fn a_run_that_came_back_carries_no_probe_failure() {
	let external = ClockExternal::default();
	let run = run_over(external.effective_sources());
	let report = compose_joined(HostClock::Synced, Ok(Ok(run)), &external);
	assert!(
		report
			.items
			.iter()
			.all(|item| item.name != "external probe"),
		"{report:?}"
	);
	assert!(report.detail.contains("diagnostic median"), "{report:?}");
}

fn assessed_run(offsets: &[Option<f64>]) -> Run {
	let external = ClockExternal::default();
	let mut run = run_over(external.effective_sources());
	run.readings = offsets
		.iter()
		.zip(&run.sources)
		.map(|(offset, source)| match offset {
			Some(offset) => ProbeReading::ok(source.clone(), *offset, 0.01),
			None => ProbeReading::failed(source.clone(), "timeout"),
		})
		.collect();
	let assessment = crate::clock::external::assessment::assessment(&external, &run.readings);
	run.outcome = assessment.outcome;
	run.median = assessment.median;
	run.smear_excluded = assessment.smear_excluded;
	run
}

fn assert_missing_median_fails(offsets: &[Option<f64>]) {
	let run = assessed_run(offsets);
	assert!(run.median.is_none());
	assert_eq!(run.outcome, Outcome::Fail);
	let report = compose(HostClock::Synced, Some(&run), &Default::default(), None);
	assert_eq!(report.status, Level::Fail, "{report:?}");
	assert!(crate::cli::status::report::any_failed(&[(
		crate::cli::status::CheckArea::Clock,
		report
	)]));
}

#[test]
fn review_no_valid_readings_preserves_failure() {
	assert_missing_median_fails(&[None, None, None]);
	assert_missing_median_fails(&[]);
}

#[test]
fn review_one_drifting_reading_preserves_failure() {
	assert_missing_median_fails(&[Some(10.0), None, None]);
}

#[test]
fn review_two_readings_with_drift_preserve_failure() {
	assert_missing_median_fails(&[Some(0.01), Some(10.0), None]);
}

#[test]
fn review_diagnostic_median_does_not_claim_the_worst_offset_verdict() {
	let run = assessed_run(&[Some(0.0), Some(0.05), Some(10.0)]);
	let report = compose(HostClock::Synced, Some(&run), &Default::default(), None);
	assert_eq!(report.status, Level::Fail);
	assert_eq!(item(&report, "external verdict").status, Level::Fail);
	let median = item(&report, "diagnostic median");
	assert_eq!(median.status, Level::Ok);
	assert!(median.detail.contains("0.050"));
	assert!(median.detail.contains("does not determine the verdict"));
}

#[test]
fn review_smear_candidate_remains_in_the_verdict() {
	let mut run = assessed_run(&[Some(0.0), Some(0.05), Some(10.0)]);
	run.sources[0] = Source::nts("first.example");
	run.sources[1] = Source::nts("second.example");
	for (reading, source) in run.readings.iter_mut().zip(&run.sources) {
		reading.source = source.clone();
	}
	let assessed =
		crate::clock::external::assessment::assessment(&Default::default(), &run.readings);
	run.smear_excluded = assessed.smear_excluded;
	assert_eq!(run.smear_excluded, Some(2));
	let report = compose(HostClock::Synced, Some(&run), &Default::default(), None);
	assert_eq!(report.status, Level::Fail);
	let diagnostic = item(&report, "smear diagnostic");
	assert!(
		diagnostic
			.detail
			.contains("this reading still affects the verdict")
	);
	assert!(!diagnostic.detail.contains("excluded"));
}

/// A probe task that fails before it reports leaves its source with no
/// reading. The source was asked, so the area names the gap instead of
/// rendering a run that silently omits it.
#[test]
fn review_a_source_without_a_reading_is_reported_rather_than_dropped() {
	let external = ClockExternal::default();
	let mut run = run_over(external.effective_sources());
	run.readings.pop();
	run.outcome = Outcome::Warn;
	let report = compose(HostClock::Synced, Some(&run), &external, None);
	let missing = item(&report, &run.sources[2].label());
	assert_eq!(missing.status, Level::Warn, "{missing:?}");
	assert!(missing.detail.contains("no reading"), "{missing:?}");
	assert_eq!(report.status, Level::Warn, "{report:?}");
}

/// The probe can be switched off for a host with no route to 123/udp or
/// 4460/tcp. The area then says so, at `ok`, and never queries a source.
#[tokio::test(flavor = "current_thread")]
async fn review_a_disabled_probe_reports_itself_without_touching_the_network() {
	let dir = tempfile::tempdir().expect("temp dir");
	let ctx = super::super::test_support::ctx(dir.path(), "[clock_external]\nenabled = false\n");
	let config = ctx.config.as_ref().expect("the file must load");
	assert!(!config.clock_external.as_ref().expect("block").enabled);
	let report = check(&ctx).await;
	assert_ne!(report.status, Level::Fail, "{report:?}");
	let note = item(&report, "external probe");
	assert_eq!(note.status, Level::Ok, "{note:?}");
	assert!(
		report.detail.contains("switched off"),
		"the summary must name the switch: {report:?}"
	);
	assert!(
		report
			.items
			.iter()
			.all(|item| item.name != "external verdict"),
		"a probe that never ran has no verdict to render: {report:?}"
	);
}

/// The default is on: a configuration file that never mentions the block, and
/// one that sets it, are both accepted and mean what they say.
#[test]
fn review_the_probe_runs_unless_the_block_says_otherwise() {
	let absent: ClockExternal = toml::from_str("").expect("empty block");
	assert!(absent.enabled);
	assert!(absent.validate().is_ok());
	let on: ClockExternal = toml::from_str("enabled = true").expect("enabled");
	assert!(on.enabled);
	let off: ClockExternal = toml::from_str("enabled = false").expect("disabled");
	assert!(!off.enabled);
	assert!(
		off.validate().is_ok(),
		"a disabled probe still has to be a valid block"
	);
}
