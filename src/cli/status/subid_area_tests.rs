//! Tests for the subordinate id check, on fixture tables only: the host's
//! /etc/subuid and /etc/subgid are never read here.

use std::path::Path;

use super::{Level, check_files};

/// Write the two tables into `dir` and run the check on them.
fn run(dir: &Path, subuid: &str, subgid: &str) -> super::AreaReport {
	let uid = dir.join("subuid");
	let gid = dir.join("subgid");
	std::fs::write(&uid, subuid).expect("write subuid");
	std::fs::write(&gid, subgid).expect("write subgid");
	check_files(&uid, &gid)
}

/// The detail of the item named `name`.
fn detail<'a>(report: &'a super::AreaReport, name: &str) -> (&'a str, Level) {
	let item = report
		.items
		.iter()
		.find(|item| item.name == name)
		.unwrap_or_else(|| panic!("no {name} item in {report:?}"));
	(item.detail.as_str(), item.status)
}

#[test]
fn an_overlap_fails_and_names_the_other_user_and_the_shared_interval() {
	let dir = tempfile::tempdir().expect("tempdir");
	let table = "jaroc:100000:65536\nglyndor-epistle:150000:65536\n";
	let report = run(dir.path(), table, "glyndor-epistle:165536:65536\n");
	assert_eq!(report.status, Level::Fail, "{report:?}");
	assert_eq!(
		detail(&report, "subuid"),
		(
			"glyndor-epistle 150000-215535 overlaps jaroc at 150000-165535",
			Level::Fail
		)
	);
	assert_eq!(
		detail(&report, "subgid"),
		(
			"glyndor-epistle 165536-231071, no other account maps these ids",
			Level::Ok
		)
	);
	assert_eq!(
		report.detail,
		"subuid: glyndor-epistle 150000-215535 overlaps jaroc at 150000-165535"
	);
}

#[test]
fn every_overlapping_user_is_named() {
	let dir = tempfile::tempdir().expect("tempdir");
	let table =
		"glyndor-epistle:100000:65536\nalice:90000:20000\nbob:160000:10\ncarol:165536:65536\n";
	let report = run(dir.path(), table, table);
	assert_eq!(
		detail(&report, "subgid"),
		(
			"glyndor-epistle 100000-165535 overlaps alice at 100000-109999, bob at 160000-160009",
			Level::Fail
		)
	);
}

#[test]
fn disjoint_ranges_are_ok() {
	let dir = tempfile::tempdir().expect("tempdir");
	let table = "jaroc:100000:65536\nglyndor-epistle:165536:65536\n";
	let report = run(dir.path(), table, table);
	assert_eq!(report.status, Level::Ok, "{report:?}");
	assert_eq!(
		report.detail,
		"glyndor-epistle 165536-231071 in subuid and subgid, no other account maps these ids"
	);
}

#[test]
fn a_missing_range_warns() {
	let dir = tempfile::tempdir().expect("tempdir");
	let report = run(dir.path(), "jaroc:100000:65536\n", "");
	assert_eq!(report.status, Level::Warn, "{report:?}");
	assert_eq!(
		detail(&report, "subuid"),
		(
			"glyndor-epistle has no range: rootless Podman cannot start its containers",
			Level::Warn
		)
	);
	let absent = check_files(&dir.path().join("none-uid"), &dir.path().join("none-gid"));
	assert_eq!(absent.status, Level::Warn, "{absent:?}");
	assert_eq!(
		detail(&absent, "subgid"),
		(
			"glyndor-epistle has no range: rootless Podman cannot start its containers",
			Level::Warn
		)
	);
}
