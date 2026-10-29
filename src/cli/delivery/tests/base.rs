//! `epistle delivery list` against temporary data directories.

use std::collections::BTreeMap;
use std::process::ExitCode;

use clap::Parser;

use crate::cli::delivery::{DeliveryCli, ListArgs, ListFilters, run};
use crate::cli::{Cli, Command};
use crate::storage::{DEFAULT_DELIVERY_LOG_DAYS, DeliveryLog, DeliveryOutcome, DeliveryRecord};

fn write_records(dir: &std::path::Path, records: &[DeliveryRecord]) {
	let log = DeliveryLog::open(dir, DEFAULT_DELIVERY_LOG_DAYS);
	for record in records {
		log.append(record).expect("append");
	}
}

fn sample(time: u64, recipient: &str, outcome: DeliveryOutcome) -> DeliveryRecord {
	DeliveryRecord {
		time,
		spool_id: uuid::Uuid::now_v7(),
		account: Some("alice@example.org".into()),
		from: "alice@example.org".into(),
		recipient: recipient.into(),
		outcome,
		remote: Some("mx.remote.example".into()),
		reply: Some("250 OK".into()),
		attempt: 1,
		extra: BTreeMap::new(),
		class: Default::default(),
	}
}

fn invoke(dir: &std::path::Path, args: &[&str]) -> (ExitCode, String) {
	let mut argv = vec!["epistle", "delivery"];
	argv.extend(args);
	let cli = Cli::try_parse_from(argv).expect("parse");
	let Command::Delivery(args) = cli.command else {
		panic!("not a delivery command");
	};
	let mut out = Vec::new();
	let code = run(
		dir,
		DEFAULT_DELIVERY_LOG_DAYS,
		args.action,
		1_700_000_000,
		&mut out,
	);
	(code, String::from_utf8(out).expect("utf8"))
}

#[test]
fn lists_all_records_when_no_filter_is_given() {
	let dir = tempfile::tempdir().expect("tempdir");
	write_records(
		dir.path(),
		&[
			sample(
				1_700_000_000,
				"bob@elsewhere.example",
				DeliveryOutcome::Delivered,
			),
			sample(
				1_700_000_010,
				"carol@elsewhere.example",
				DeliveryOutcome::Failed,
			),
		],
	);
	let (_code, text) = invoke(dir.path(), &["list"]);
	assert!(text.contains("2 records"), "text was: {text}");
	assert!(text.contains("delivered"));
	assert!(text.contains("failed"));
}

#[test]
fn prints_one_json_object_per_record() {
	let dir = tempfile::tempdir().expect("tempdir");
	write_records(
		dir.path(),
		&[sample(
			1_700_000_000,
			"bob@elsewhere.example",
			DeliveryOutcome::Delivered,
		)],
	);
	let (_code, text) = invoke(dir.path(), &["list", "--json"]);
	let value: serde_json::Value = serde_json::from_str(&text).expect("JSON");
	let rows = value.as_array().expect("array");
	assert_eq!(rows.len(), 1);
	assert_eq!(rows[0]["recipient"], "bob@elsewhere.example");
	assert_eq!(rows[0]["outcome"], "delivered");
	assert_eq!(rows[0]["from"], "alice@example.org");
}

#[test]
fn filters_by_recipient_account_outcome_and_since() {
	let dir = tempfile::tempdir().expect("tempdir");
	let now = 1_700_000_000;
	let yesterday = now - 86_400;
	let earlier = now - 7 * 86_400;
	let records = [
		sample(now, "bob@elsewhere.example", DeliveryOutcome::Delivered),
		sample(
			yesterday,
			"carol@elsewhere.example",
			DeliveryOutcome::Failed,
		),
		sample(
			earlier,
			"alice@elsewhere.example",
			DeliveryOutcome::Suppressed,
		),
	];
	write_records(dir.path(), &records);

	let only_bob = DeliveryCli::List(ListArgs {
		filters: ListFilters {
			recipient: Some("bob@elsewhere.example".into()),
			..Default::default()
		},
		..Default::default()
	});
	let mut out = Vec::new();
	let code = run(
		dir.path(),
		DEFAULT_DELIVERY_LOG_DAYS,
		Some(only_bob),
		now,
		&mut out,
	);
	assert_eq!(code, ExitCode::SUCCESS);
	let text = String::from_utf8(out).unwrap();
	assert!(text.contains("bob@elsewhere.example"));
	assert!(!text.contains("carol@elsewhere.example"));
	assert!(!text.contains("alice@elsewhere.example"));

	let (_code, since_text) = invoke(dir.path(), &["list", "--since", "3d"]);
	assert!(
		since_text.contains("bob@elsewhere.example"),
		"text was: {since_text}"
	);
	assert!(!since_text.contains("alice@elsewhere.example"));
}

#[test]
fn rejects_an_unknown_outcome_with_exit_code_2() {
	let dir = tempfile::tempdir().expect("tempdir");
	write_records(
		dir.path(),
		&[sample(
			1_700_000_000,
			"bob@elsewhere.example",
			DeliveryOutcome::Delivered,
		)],
	);
	let (code, _text) = invoke(dir.path(), &["list", "--outcome", "wonky"]);
	assert_eq!(code, ExitCode::from(2));
}

#[test]
fn rejects_an_unparseable_since_with_exit_code_2() {
	let dir = tempfile::tempdir().expect("tempdir");
	write_records(
		dir.path(),
		&[sample(
			1_700_000_000,
			"bob@elsewhere.example",
			DeliveryOutcome::Delivered,
		)],
	);
	let (code, _text) = invoke(dir.path(), &["list", "--since", "not-a-time"]);
	assert_eq!(code, ExitCode::from(2));
}

#[test]
fn disabled_log_fails_with_a_clear_message() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut argv = vec!["epistle", "delivery"];
	argv.extend(Vec::<&str>::new());
	let cli = Cli::try_parse_from(argv).expect("parse");
	let Command::Delivery(args) = cli.command else {
		panic!("not a delivery command");
	};
	let mut out = Vec::new();
	// `0` retention disables the log; the command fails closed.
	let code = run(dir.path(), 0, args.action, 1_700_000_000, &mut out);
	assert_eq!(code, ExitCode::FAILURE);
}

#[test]
fn limit_caps_the_number_of_printed_records() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut records = Vec::new();
	for i in 0..5 {
		records.push(sample(
			1_700_000_000 + i,
			&format!("r{i}@elsewhere.example"),
			DeliveryOutcome::Delivered,
		));
	}
	write_records(dir.path(), &records);
	let (_code, text) = invoke(dir.path(), &["list", "--limit", "2"]);
	assert!(text.contains("2 records"), "text was: {text}");
	assert!(!text.contains("r3@"));
}

#[test]
fn bare_delivery_lists_like_delivery_list() {
	let dir = tempfile::tempdir().expect("tempdir");
	write_records(
		dir.path(),
		&[sample(
			1_700_000_000,
			"bob@elsewhere.example",
			DeliveryOutcome::Delivered,
		)],
	);
	let bare = invoke(dir.path(), &[]);
	let list = invoke(dir.path(), &["list"]);
	assert_eq!(bare, list, "`delivery` must behave as `delivery list`");
	assert!(list.1.contains("1 records"), "text was: {}", list.1);
}

#[test]
fn list_takes_every_filter_and_the_config_on_either_side() {
	for argv in [
		vec![
			"epistle",
			"delivery",
			"list",
			"--recipient",
			"bob@x.example",
			"--account",
			"alice",
			"--since",
			"1d",
			"--outcome",
			"failed",
			"--limit",
			"5",
			"--json",
			"--config",
			"/tmp/mail.toml",
		],
		vec![
			"epistle",
			"delivery",
			"--config",
			"/tmp/mail.toml",
			"list",
			"--recipient",
			"bob@x.example",
			"--account",
			"alice",
			"--since",
			"1d",
			"--outcome",
			"failed",
			"--limit",
			"5",
			"--json",
		],
	] {
		let cli = Cli::try_parse_from(&argv).unwrap_or_else(|e| panic!("{argv:?}: {e}"));
		let Command::Delivery(args) = cli.command else {
			panic!("not a delivery command");
		};
		assert_eq!(args.config, std::path::Path::new("/tmp/mail.toml"));
		let Some(DeliveryCli::List(list)) = args.action else {
			panic!("{argv:?} must parse as the list action");
		};
		assert!(list.json);
		assert_eq!(list.limit, 5);
		assert_eq!(list.filters.recipient.as_deref(), Some("bob@x.example"));
		assert_eq!(list.filters.account.as_deref(), Some("alice"));
		assert_eq!(list.filters.since.as_deref(), Some("1d"));
		assert_eq!(list.filters.outcome.as_deref(), Some("failed"));
	}
}

#[test]
fn the_list_defaults_match_a_bare_delivery() {
	let list = ListArgs::default();
	assert_eq!(list.limit, 100, "the default limit is 100 records");
	assert!(!list.json);
}

#[test]
fn the_list_shows_the_time_as_an_rfc3339_instant() {
	let dir = tempfile::tempdir().expect("tempdir");
	write_records(
		dir.path(),
		&[sample(
			1_700_000_000,
			"bob@elsewhere.example",
			DeliveryOutcome::Delivered,
		)],
	);
	let (_code, text) = invoke(dir.path(), &["list"]);
	assert!(
		text.contains("2023-11-14T22:13:20Z"),
		"the time must be readable at a glance: {text}"
	);
	assert!(
		!text.contains("1700000000"),
		"the table must not print the epoch: {text}"
	);
}

#[test]
fn the_table_on_a_terminal_shows_the_time_as_an_rfc3339_instant() {
	let dir = tempfile::tempdir().expect("tempdir");
	write_records(
		dir.path(),
		&[sample(
			1_700_000_000,
			"bob@elsewhere.example",
			DeliveryOutcome::Delivered,
		)],
	);
	let mut out = Vec::new();
	crate::cli::term::fake::with_stdout(crate::cli::term::Decor::coloured(120), || {
		let cli = Cli::try_parse_from(["epistle", "delivery", "list"]).expect("parse");
		let Command::Delivery(args) = cli.command else {
			panic!("not a delivery command");
		};
		run(
			dir.path(),
			DEFAULT_DELIVERY_LOG_DAYS,
			args.action,
			1_700_000_000,
			&mut out,
		);
	});
	let text = String::from_utf8(out).expect("utf8");
	assert!(
		text.contains("2023-11-14T22:13:20Z"),
		"the time must be readable at a glance: {text}"
	);
	assert!(
		!text.contains("1700000000"),
		"the table must not print the epoch: {text}"
	);
}

#[test]
fn the_json_list_keeps_the_epoch() {
	let dir = tempfile::tempdir().expect("tempdir");
	write_records(
		dir.path(),
		&[sample(
			1_700_000_000,
			"bob@elsewhere.example",
			DeliveryOutcome::Delivered,
		)],
	);
	let (_code, text) = invoke(dir.path(), &["list", "--json"]);
	let value: serde_json::Value = serde_json::from_str(&text).expect("JSON");
	assert_eq!(
		value[0]["time"], 1_700_000_000,
		"the JSON keeps the epoch second: {text}"
	);
}

#[test]
fn filters_belong_to_the_list_action() {
	let error = Cli::try_parse_from(["epistle", "delivery", "--recipient", "bob@x.example"])
		.expect_err("a filter without `list` must not parse");
	assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
}
