//! Tests for reading the DMARC aggregate reports into the warning the
//! plan shows before a policy step.

use std::path::Path;

use super::*;
use crate::reports::dmarc::{DateRange, DmarcReport, PolicyPublished, Row};

/// 2026-10-14 12:00 UTC.
const NOW: u64 = 1_791_979_200;

fn row(ip: &str, count: u64, disposition: &str, dkim: &str, spf: &str) -> Row {
	Row {
		source_ip: ip.into(),
		count,
		disposition: disposition.into(),
		dkim: dkim.into(),
		spf: spf.into(),
		header_from: "example.org".into(),
	}
}

fn report(domain: &str, records: Vec<Row>) -> DmarcReport {
	DmarcReport {
		org_name: "receiver.example".into(),
		email: None,
		report_id: "r1".into(),
		date_range: DateRange { begin: 0, end: 0 },
		policy_published: PolicyPublished {
			domain: domain.into(),
			p: "none".into(),
			sp: None,
			pct: 100,
		},
		records,
		truncated: false,
	}
}

fn store(data_dir: &Path, day: &str, file: &str, reports: &[DmarcReport]) {
	let dir = data_dir.join("reports").join("dmarc").join(day);
	std::fs::create_dir_all(&dir).expect("mkdir");
	let lines: Vec<String> = reports
		.iter()
		.map(|r| serde_json::to_string(r).expect("json"))
		.collect();
	std::fs::write(dir.join(file), lines.join("\n") + "\n").expect("write");
}

#[test]
fn failing_senders_are_summed_per_source_most_messages_first() {
	let dir = tempfile::tempdir().expect("tempdir");
	store(
		dir.path(),
		"20261010",
		"receiver.example.jsonl",
		&[
			report(
				"example.org",
				vec![
					row("192.0.2.10", 1, "quarantine", "pass", "fail"),
					row("192.0.2.10", 4, "none", "fail", "fail"),
					row("203.0.113.5", 9, "reject", "fail", "pass"),
					row("198.51.100.1", 50, "none", "pass", "pass"),
					row("198.51.100.2", 7, "none", "fail", "pass"),
				],
			),
			report(
				"other.example",
				vec![row("203.0.113.99", 100, "reject", "fail", "fail")],
			),
		],
	);
	let (sources, seen) = recent_dmarc_failures(dir.path(), "example.org", NOW);
	assert!(seen);
	assert_eq!(
		sources,
		vec![
			FailingSource {
				source_ip: "203.0.113.5".into(),
				messages: 9
			},
			FailingSource {
				source_ip: "192.0.2.10".into(),
				messages: 5
			},
		]
	);
}

#[test]
fn reports_older_than_the_window_or_for_another_domain_do_not_count() {
	let dir = tempfile::tempdir().expect("tempdir");
	let failing = vec![row("192.0.2.10", 3, "reject", "fail", "fail")];
	store(
		dir.path(),
		"20260901",
		"old.jsonl",
		&[report("example.org", failing.clone())],
	);
	store(
		dir.path(),
		"20261012",
		"other.jsonl",
		&[report("other.example", failing.clone())],
	);
	store(
		dir.path(),
		"20261012",
		"notes.txt",
		&[report("example.org", failing)],
	);
	assert_eq!(
		recent_dmarc_failures(dir.path(), "example.org", NOW),
		(Vec::new(), false)
	);
}

#[test]
fn reports_without_a_failure_say_reports_exist() {
	let dir = tempfile::tempdir().expect("tempdir");
	store(
		dir.path(),
		"20261013",
		"r.jsonl",
		&[report(
			"Example.ORG",
			vec![row("192.0.2.1", 5, "none", "pass", "fail")],
		)],
	);
	assert_eq!(
		recent_dmarc_failures(dir.path(), "example.org", NOW),
		(Vec::new(), true)
	);
}

#[test]
fn no_report_store_means_no_reports() {
	let dir = tempfile::tempdir().expect("tempdir");
	assert_eq!(
		recent_dmarc_failures(dir.path(), "example.org", NOW),
		(Vec::new(), false)
	);
}
