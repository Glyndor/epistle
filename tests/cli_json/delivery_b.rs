//! `delivery show`, `delivery export`, and the `--until` and `--status`
//! filters of the delivery log commands.

use std::collections::BTreeMap;

use serde_json::Value;
use uuid::Uuid;

use epistle::storage::{DeliveryLog, DeliveryOutcome, DeliveryRecord};

use crate::harness::{Env, env, epistle};

/// 2023-11-14T22:13:20Z.
const BASE: u64 = 1_700_000_000;
const FIRST: Uuid = Uuid::from_u128(0x0123_4567_89ab_7cde_8f01_2345_6789_abcd);
const SECOND: Uuid = Uuid::from_u128(0x0123_4567_89ab_7cde_8f01_2345_6789_abce);

fn record(offset: u64, id: Uuid, recipient: &str, outcome: DeliveryOutcome) -> DeliveryRecord {
	DeliveryRecord {
		time: BASE + offset,
		spool_id: id,
		account: Some("alice".into()),
		from: "alice@example.org".into(),
		recipient: recipient.into(),
		outcome,
		remote: Some("mx.remote.example".into()),
		reply: Some("250 2.0.0 OK".into()),
		attempt: 1,
		extra: BTreeMap::new(),
	}
}

fn seeded(records: &[DeliveryRecord]) -> Env {
	let env = env("[storage]\ndelivery_log_days = 30\n");
	let log = DeliveryLog::open(&env.data_dir(), 30);
	for record in records {
		log.append(record).expect("append");
	}
	env
}

fn four() -> Env {
	seeded(&[
		record(0, FIRST, "a@remote.example", DeliveryOutcome::Delivered),
		record(10, FIRST, "b@remote.example", DeliveryOutcome::Failed),
		record(20, SECOND, "c@remote.example", DeliveryOutcome::Deferred),
		record(30, SECOND, "d@remote.example", DeliveryOutcome::Delivered),
	])
}

fn run(env: &Env, args: &[&str]) -> (i32, Value) {
	let mut full = vec!["delivery", "--config", &env.config];
	full.extend_from_slice(args);
	full.push("--json");
	json_any(&full)
}

/// `json` wants one line; the list prints an indented array, so parse the
/// whole of stdout as one document instead.
fn json_any(full: &[&str]) -> (i32, Value) {
	let output = epistle(full, b"");
	let stdout = String::from_utf8_lossy(&output.stdout);
	let value = serde_json::from_str(&stdout).unwrap_or_else(|error| {
		panic!(
			"stdout is not one JSON document: {error}; stderr: {}",
			String::from_utf8_lossy(&output.stderr)
		)
	});
	(output.status.code().unwrap_or(-1), value)
}

fn plain(env: &Env, args: &[&str]) -> (Option<i32>, String, String) {
	let mut full = vec!["delivery", "--config", &env.config];
	full.extend_from_slice(args);
	let output = epistle(&full, b"");
	(
		output.status.code(),
		String::from_utf8_lossy(&output.stdout).into_owned(),
		String::from_utf8_lossy(&output.stderr).into_owned(),
	)
}

fn recipients(rows: &Value) -> Vec<&str> {
	let mut found: Vec<&str> = rows
		.as_array()
		.expect("array")
		.iter()
		.map(|row| row["recipient"].as_str().expect("recipient"))
		.collect();
	found.sort_unstable();
	found
}

#[test]
fn since_and_until_bound_the_records_in_time() {
	let env = four();
	let (_, between) = run(
		&env,
		&[
			"list",
			"--since",
			"2023-11-14T22:13:30Z",
			"--until",
			"2023-11-14T22:13:40Z",
		],
	);
	assert_eq!(
		recipients(&between),
		["b@remote.example", "c@remote.example"]
	);
	let (_, until) = run(&env, &["list", "--until", "2023-11-14T22:13:30Z"]);
	assert_eq!(recipients(&until), ["a@remote.example", "b@remote.example"]);
}

#[test]
fn status_is_the_outcome_filter_under_its_other_name() {
	let env = four();
	let (_, by_status) = run(&env, &["list", "--status", "delivered"]);
	let (_, by_outcome) = run(&env, &["list", "--outcome", "delivered"]);
	assert_eq!(by_status, by_outcome);
	assert_eq!(
		recipients(&by_status),
		["a@remote.example", "d@remote.example"]
	);
	let (code, stdout, stderr) = plain(&env, &["list", "--status", "gone", "--json"]);
	assert_eq!((code, stdout.as_str()), (Some(2), ""));
	assert!(
		stderr.contains("unknown status \"gone\" for --outcome (or --status)"),
		"{stderr}"
	);
}

#[test]
fn a_window_that_ends_before_it_starts_is_refused() {
	let env = four();
	let (code, stdout, stderr) = plain(
		&env,
		&[
			"list",
			"--since",
			"2023-11-14T22:13:40Z",
			"--until",
			"2023-11-14T22:13:30Z",
			"--json",
		],
	);
	assert_eq!((code, stdout.as_str()), (Some(2), ""));
	assert_eq!(stderr.trim_end(), "error: --since is after --until");
	let (code, stdout, stderr) = plain(&env, &["list", "--until", "tomorrow", "--json"]);
	assert_eq!((code, stdout.as_str()), (Some(2), ""));
	assert!(stderr.contains("--until \"tomorrow\""), "{stderr}");
}

#[test]
fn show_prints_every_record_of_one_message() {
	let env = four();
	let (code, shown) = run(&env, &["show", &FIRST.to_string()]);
	assert_eq!(code, 0);
	assert_eq!(shown["spool_id"], FIRST.to_string());
	assert_eq!(
		recipients(&shown["records"]),
		["a@remote.example", "b@remote.example"]
	);
	assert_eq!(
		shown["records"][0]["recipient"], "a@remote.example",
		"oldest first"
	);
	assert_eq!(shown["records"][1]["recipient"], "b@remote.example");
	let (code, text, _) = plain(&env, &["show", &FIRST.to_string()]);
	assert_eq!(code, Some(0));
	assert!(text.starts_with(&format!("message\t{FIRST}\n")), "{text}");
	assert!(text.contains("recipient\ta@remote.example\n"), "{text}");
	assert!(text.contains("2023-11-14T22:13:20Z"), "{text}");
	assert!(
		!text.contains("c@remote.example"),
		"a record of another message: {text}"
	);
}

#[test]
fn show_of_an_unknown_or_malformed_id_is_refused() {
	let env = four();
	let missing = Uuid::from_u128(7).to_string();
	let (code, stdout, stderr) = plain(&env, &["show", &missing, "--json"]);
	assert_eq!((code, stdout.as_str()), (Some(2), ""));
	assert_eq!(
		stderr.trim_end(),
		format!("error: no delivery records for {missing}")
	);
	let (code, stdout, stderr) = plain(&env, &["show", "not-an-id\u{1b}[2J", "--json"]);
	assert_eq!((code, stdout.as_str()), (Some(2), ""));
	assert!(stderr.contains("is not a message id"), "{stderr}");
	assert!(!stderr.contains('\u{1b}'), "{stderr:?}");
}

#[test]
fn show_escapes_what_a_remote_server_said() {
	let mut hostile = record(0, FIRST, "a@remote.example", DeliveryOutcome::Failed);
	hostile.reply = Some("550 gone\u{1b}[2J\u{7}away".into());
	hostile.remote = Some("mx\u{1b}[31m.remote.example".into());
	let env = seeded(&[hostile]);
	let (_, text, _) = plain(&env, &["show", &FIRST.to_string()]);
	assert!(
		!text.contains('\u{1b}') && !text.contains('\u{7}'),
		"{text:?}"
	);
	assert!(text.contains("550 gone\\u{1b}[2J\\u{7}away"), "{text:?}");
}

#[test]
fn export_writes_csv_with_the_filters_applied() {
	let mut formula = record(40, SECOND, "e@remote.example", DeliveryOutcome::Failed);
	formula.reply = Some("=HYPERLINK(\"http://x.example\",\"pay\")".into());
	let env = seeded(&[
		record(0, FIRST, "a@remote.example", DeliveryOutcome::Delivered),
		record(10, FIRST, "b@remote.example", DeliveryOutcome::Failed),
		formula,
	]);
	let (code, csv, _) = plain(&env, &["export", "--status", "failed"]);
	assert_eq!(code, Some(0));
	let lines: Vec<&str> = csv.lines().collect();
	assert_eq!(
		lines[0],
		"time,outcome,spool_id,account,from,recipient,remote,reply,attempt"
	);
	assert_eq!(lines.len(), 3, "{csv}");
	assert!(
		lines.iter().any(|line| line.starts_with(&format!(
			"2023-11-14T22:13:30Z,failed,{FIRST},alice,alice@example.org,b@remote.example,mx.remote.example,250 2.0.0 OK,1"
		))),
		"{csv}"
	);
	assert!(
		lines
			.iter()
			.any(|line| line.contains(",\"'=HYPERLINK(\"\"http://x.example\"\",\"\"pay\"\")\",")),
		"a formula must not leave the export as one: {csv}"
	);
}

#[test]
fn export_as_json_is_an_array_of_the_records() {
	let env = four();
	let (code, rows) = run(&env, &["export", "--recipient", "c@remote.example"]);
	assert_eq!(code, 0);
	assert_eq!(rows.as_array().map(Vec::len), Some(1));
	assert_eq!(rows[0]["spool_id"], SECOND.to_string());
	assert_eq!(rows[0]["outcome"], "deferred");
}

#[test]
fn export_is_bounded() {
	let env = four();
	for limit in ["0", "100001"] {
		let (code, stdout, stderr) = plain(&env, &["export", "--limit", limit, "--json"]);
		assert_eq!((code, stdout.as_str()), (Some(2), ""), "{limit}");
		assert!(
			stderr.contains("--limit must be between 1 and 100000"),
			"{limit}: {stderr}"
		);
	}
	let (_, one) = run(&env, &["export", "--limit", "1"]);
	assert_eq!(one.as_array().map(Vec::len), Some(1));
}

#[test]
fn the_new_commands_need_the_log_to_be_on() {
	let env = env("[storage]\ndelivery_log_days = 0\n");
	for args in [
		vec!["show", &FIRST.to_string(), "--json"],
		vec!["export", "--json"],
	] {
		let (code, stdout, stderr) = plain(&env, &args);
		assert_eq!((code, stdout.as_str()), (Some(1), ""), "{args:?}");
		assert!(stderr.contains("the delivery log is disabled"), "{stderr}");
	}
}

#[test]
fn a_filter_that_is_empty_is_a_usage_error_not_no_filter() {
	let env = four();
	for flag in [
		"--account",
		"--recipient",
		"--since",
		"--until",
		"--outcome",
		"--status",
	] {
		for value in ["", "  "] {
			for action in ["list", "export"] {
				let (code, stdout, stderr) = plain(&env, &[action, flag, value, "--json"]);
				assert_eq!(
					(code, stdout.as_str()),
					(Some(2), ""),
					"{action} {flag} {value:?}"
				);
				let shown = flag.replace("--status", "--outcome");
				assert_eq!(
					stderr.trim_end(),
					format!("error: {shown} must not be empty"),
					"{action} {flag} {value:?}"
				);
			}
		}
	}
}
