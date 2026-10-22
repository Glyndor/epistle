//! Tests for the clock area: rendering the host probe verdict; the
//! external probe path exercises its own internal tests.

use std::time::Instant;

use super::{HostClock, compose};
use crate::cli::status::report::{AreaReport, Item, Level};
use crate::clock::external::{ClockExternal, Outcome, ProbeReading, Run, SignedOffset, Source};

#[test]
fn a_synchronised_host_renders_ok_without_fix_suggestions() {
	let report = compose(HostClock::Synced, None, &Default::default());
	assert_eq!(report.status, Level::Ok, "{report:?}");
	assert_eq!(report.detail, "external clock probe not run");
	assert!(
		report.items.iter().all(|item| item.status == Level::Ok),
		"{report:?}"
	);
}

#[test]
fn an_unsynchronised_host_warns_and_names_the_fixes() {
	let report = compose(HostClock::Unsynced, None, &Default::default());
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
	report
		.items
		.iter()
		.find(|item| item.name == name)
		.unwrap_or_else(|| panic!("the area must report {name}: {report:?}"))
}

/// The default list carries one authenticated source, so the area must say
/// so instead of rendering three offsets that read as equally trusted.
#[test]
fn the_area_names_how_many_sources_were_authenticated() {
	let external = ClockExternal::default();
	let run = run_over(external.effective_sources());
	let report = compose(HostClock::Synced, Some(&run), &external);
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
	let report = compose(HostClock::Synced, Some(&run), &external);
	let note = item(&report, "authentication");
	assert_eq!(note.status, Level::Warn, "{note:?}");
	assert!(
		note.detail
			.contains("no source in this run is NTS-authenticated"),
		"{note:?}"
	);
}
