//! The `deliverability` check: one warning per panel not enrolled in, and
//! never a failure.

use std::process::ExitCode;

use super::check;
use crate::cli::status::report::Level;
use crate::cli::status::test_support::ctx;
use crate::cli::status::{CheckArea, execute};
use crate::config::Portal;

fn report(extra: &str) -> crate::cli::status::report::AreaReport {
	let dir = tempfile::tempdir().expect("tempdir");
	let ctx = ctx(dir.path(), extra);
	tokio::runtime::Runtime::new()
		.expect("runtime")
		.block_on(check(&ctx))
}

fn names(report: &crate::cli::status::report::AreaReport) -> Vec<&str> {
	report.items.iter().map(|item| item.name.as_str()).collect()
}

#[test]
fn an_empty_list_warns_about_every_panel() {
	let report = report("");
	assert_eq!(report.status, Level::Warn, "{report:?}");
	assert_eq!(
		names(&report),
		["postmaster", "snds", "jmrp", "yahoo-cfl", "apple"]
	);
	for (item, portal) in report.items.iter().zip(Portal::ALL) {
		assert_eq!(item.status, Level::Warn);
		assert!(item.detail.contains(portal.what()), "{item:?}");
		assert!(item.detail.contains(portal.page()), "{item:?}");
		assert!(item.detail.contains("docs/operations/providers.md"));
	}
	assert!(report.detail.contains("5 of 5"), "{}", report.detail);
}

#[test]
fn a_marked_panel_stops_being_reported() {
	let report = report("[deliverability]\nenrolled = ['postmaster', 'snds', 'jmrp']\n");
	assert_eq!(report.status, Level::Warn);
	assert_eq!(names(&report), ["yahoo-cfl", "apple"]);
	assert!(report.detail.contains("2 of 5"), "{}", report.detail);
}

#[test]
fn every_panel_marked_is_ok_with_no_findings() {
	let report = report(
		"[deliverability]\nenrolled = ['postmaster', 'snds', 'jmrp', 'yahoo-cfl', 'apple']\n",
	);
	assert_eq!(report.status, Level::Ok, "{report:?}");
	assert!(report.items.is_empty());
}

#[test]
fn the_area_never_fails_on_its_own() {
	for extra in ["", "[deliverability]\nenrolled = ['apple']\n"] {
		assert_ne!(report(extra).status, Level::Fail);
	}
}

#[test]
fn the_check_never_blocks_the_exit_code() {
	let dir = tempfile::tempdir().expect("tempdir");
	let path = {
		let ctx = ctx(dir.path(), "");
		ctx.path
	};
	let mut out = Vec::new();
	let code = execute(&path, &[CheckArea::Deliverability], false, true, &mut out);
	let text = String::from_utf8(out).expect("utf8");
	assert!(text.contains("warn"), "{text}");
	assert!(text.contains("postmaster"), "{text}");
	assert_eq!(code, ExitCode::SUCCESS);
}

#[test]
fn the_area_is_part_of_the_status_run_and_the_json_key_is_deliverability() {
	let dir = tempfile::tempdir().expect("tempdir");
	let path = ctx(dir.path(), "").path;
	assert!(CheckArea::ALL.contains(&CheckArea::Deliverability));
	assert_eq!(CheckArea::Deliverability.name(), "deliverability");
	let mut out = Vec::new();
	let _ = execute(&path, &[CheckArea::Deliverability], true, false, &mut out);
	let value: serde_json::Value = serde_json::from_slice(&out).expect("valid JSON");
	assert_eq!(value["deliverability"]["status"], "warn", "{value}");
}

#[test]
fn a_configuration_that_does_not_load_is_reported_not_guessed() {
	let report = report("[deliverability]\nenrolled = ['gmx']\n");
	assert_eq!(report.status, Level::Fail, "{report:?}");
}
