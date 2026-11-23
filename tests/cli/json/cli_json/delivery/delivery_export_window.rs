//! `delivery export --since` and `--until`: the export is the audit copy of
//! the delivery log, so the window it is cut to has to be the one asked for,
//! in both of its formats, and a window that cannot be read stops the export
//! before it prints a line.

use std::collections::BTreeMap;

use serde_json::Value;
use uuid::Uuid;

use epistle::storage::{DeliveryLog, DeliveryOutcome, DeliveryRecord};

use crate::harness::{Env, env, epistle};

/// 2023-11-14T22:13:20Z.
const BASE: u64 = 1_700_000_000;
const MESSAGE: Uuid = Uuid::from_u128(0x0123_4567_89ab_7cde_8f01_2345_6789_abd0);

fn record(offset: u64, recipient: &str, outcome: DeliveryOutcome) -> DeliveryRecord {
	DeliveryRecord {
		time: BASE + offset,
		spool_id: MESSAGE,
		account: Some("alice".into()),
		from: "alice@example.org".into(),
		recipient: recipient.into(),
		outcome,
		remote: Some("mx.remote.example".into()),
		reply: Some("250 2.0.0 OK".into()),
		attempt: 1,
		extra: BTreeMap::new(),
		class: epistle::evidence::MailClass::default(),
	}
}

/// Four records, ten seconds apart, from `a` at 22:13:20 to `d` at 22:13:50.
fn log() -> Env {
	let env = env("[storage]\ndelivery_log_days = 30\n");
	let log = DeliveryLog::open(&env.data_dir(), 30);
	for (offset, recipient, outcome) in [
		(0, "a@remote.example", DeliveryOutcome::Delivered),
		(10, "b@remote.example", DeliveryOutcome::Failed),
		(20, "c@remote.example", DeliveryOutcome::Deferred),
		(30, "d@remote.example", DeliveryOutcome::Delivered),
	] {
		log.append(&record(offset, recipient, outcome))
			.expect("append");
	}
	env
}

fn export(env: &Env, args: &[&str]) -> (Option<i32>, String, String) {
	let mut full = vec!["delivery", "--config", &env.config, "export"];
	full.extend_from_slice(args);
	let output = epistle(&full, b"");
	(
		output.status.code(),
		String::from_utf8_lossy(&output.stdout).into_owned(),
		String::from_utf8_lossy(&output.stderr).into_owned(),
	)
}

/// The recipients of a CSV export, in the order printed.
fn csv_recipients(csv: &str) -> Vec<&str> {
	csv.lines()
		.skip(1)
		.map(|line| line.split(',').nth(5).expect("recipient column"))
		.collect()
}

fn json_recipients(text: &str) -> Vec<String> {
	let rows: Value = serde_json::from_str(text).expect("a JSON array");
	rows.as_array()
		.expect("array")
		.iter()
		.map(|row| row["recipient"].as_str().expect("recipient").to_string())
		.collect()
}

#[test]
fn since_and_until_cut_the_export_to_the_window_with_both_ends_included() {
	let env = log();
	let (code, csv, _) = export(
		&env,
		&[
			"--since",
			"2023-11-14T22:13:30Z",
			"--until",
			"2023-11-14T22:13:40Z",
		],
	);
	assert_eq!(code, Some(0));
	let mut found = csv_recipients(&csv);
	found.sort_unstable();
	assert_eq!(found, ["b@remote.example", "c@remote.example"], "{csv}");

	let (code, text, _) = export(
		&env,
		&[
			"--since",
			"2023-11-14T22:13:30Z",
			"--until",
			"2023-11-14T22:13:40Z",
			"--json",
		],
	);
	assert_eq!(code, Some(0));
	let mut found = json_recipients(&text);
	found.sort_unstable();
	assert_eq!(found, ["b@remote.example", "c@remote.example"]);
}

#[test]
fn each_end_of_the_window_works_alone() {
	let env = log();
	let (_, text, _) = export(&env, &["--since", "2023-11-14T22:13:40Z", "--json"]);
	let mut found = json_recipients(&text);
	found.sort_unstable();
	assert_eq!(found, ["c@remote.example", "d@remote.example"]);
	let (_, text, _) = export(&env, &["--until", "2023-11-14T22:13:20Z", "--json"]);
	assert_eq!(json_recipients(&text), ["a@remote.example"]);
}

#[test]
fn the_window_combines_with_the_other_filters() {
	let env = log();
	let (_, text, _) = export(
		&env,
		&[
			"--since",
			"2023-11-14T22:13:20Z",
			"--until",
			"2023-11-14T22:13:50Z",
			"--status",
			"delivered",
			"--json",
		],
	);
	let mut found = json_recipients(&text);
	found.sort_unstable();
	assert_eq!(found, ["a@remote.example", "d@remote.example"]);
	let (_, text, _) = export(
		&env,
		&[
			"--since",
			"2023-11-14T22:13:30Z",
			"--status",
			"delivered",
			"--json",
		],
	);
	assert_eq!(json_recipients(&text), ["d@remote.example"]);
}

#[test]
fn a_window_with_nothing_in_it_is_an_empty_export_and_not_an_error() {
	let env = log();
	let (code, text, _) = export(
		&env,
		&[
			"--since",
			"2023-11-15T00:00:00Z",
			"--until",
			"2023-11-16T00:00:00Z",
			"--json",
		],
	);
	assert_eq!(code, Some(0));
	assert!(json_recipients(&text).is_empty());
	let (code, csv, _) = export(&env, &["--since", "2023-11-15T00:00:00Z"]);
	assert_eq!(code, Some(0));
	assert_eq!(csv.lines().count(), 1, "only the header: {csv}");
	// A recent window cuts old records away: everything here is from 2023.
	let (code, text, _) = export(&env, &["--since", "24h", "--json"]);
	assert_eq!(code, Some(0));
	assert!(json_recipients(&text).is_empty());
}

#[test]
fn a_window_that_cannot_be_read_stops_the_export_before_it_prints() {
	let env = log();
	for (args, why) in [
		(
			&[
				"--since",
				"2023-11-14T22:13:40Z",
				"--until",
				"2023-11-14T22:13:30Z",
			][..],
			"--since is after --until",
		),
		(&["--since", "last tuesday"][..], "--since \"last tuesday\""),
		(&["--until", "2023-13-45"][..], "--until \"2023-13-45\""),
	] {
		let (code, stdout, stderr) = export(&env, args);
		assert_eq!((code, stdout.as_str()), (Some(2), ""), "{args:?}");
		assert!(stderr.contains(why), "{args:?}: {stderr}");
	}
}
