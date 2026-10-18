//! Tests for the clock check on injected host readings.

use super::{HostClock, Level, evaluate};
use crate::cli::status::CheckArea;
use crate::cli::status::report::render_json;

#[test]
fn a_synchronised_clock_is_ok_and_suggests_nothing() {
	let report = evaluate(&HostClock::Synced);
	assert_eq!(report.status, Level::Ok, "{report:?}");
	assert_eq!(report.detail, "synchronised");
	assert!(report.items.iter().all(|item| item.name != "to fix"));
}

#[test]
fn an_unsynchronised_clock_warns_and_names_the_fixes() {
	let report = evaluate(&HostClock::Unsynced);
	assert_eq!(report.status, Level::Warn, "{report:?}");
	assert_eq!(report.detail, "not synchronised");
	assert!(
		report.items.iter().all(|item| item.status == Level::Warn),
		"{report:?}"
	);
	let fix = report
		.items
		.iter()
		.find(|item| item.name == "to fix")
		.expect("fix item");
	for needle in [
		"timedatectl set-ntp true",
		"NTP=time.cloudflare.com",
		"/etc/systemd/timesyncd.conf",
		"chrony",
		"never Cloudflare and Google together",
	] {
		assert!(fix.detail.contains(needle), "{needle}: {}", fix.detail);
	}
}

#[test]
fn a_clock_that_cannot_be_read_warns_with_the_reason_instead_of_guessing() {
	let report = evaluate(&HostClock::Unknown("no adjtimex".to_string()));
	assert_eq!(report.status, Level::Warn, "{report:?}");
	assert_eq!(report.detail, "cannot tell whether it is synchronised");
	assert!(report.items[0].detail.contains("no adjtimex"), "{report:?}");
	assert_eq!(report.items[0].status, Level::Warn, "{report:?}");
}

#[test]
fn json_carries_the_clock_area_with_status_detail_and_items() {
	let reports = [(CheckArea::Clock, evaluate(&HostClock::Unsynced))];
	let mut out = Vec::new();
	render_json(&reports, &mut out).expect("render");
	let value: serde_json::Value = serde_json::from_slice(&out).expect("json");
	assert_eq!(value["clock"]["status"], "warn");
	assert_eq!(value["clock"]["detail"], "not synchronised");
	assert_eq!(value["clock"]["items"][1]["name"], "to fix");
}
