//! `epistle queue` actions against temporary spool directories.

use super::*;
use crate::cli::{Cli, Command};
use crate::smtp::session::AcceptedMessage;
use clap::Parser;

const BODY: &str = "Subject: hi\r\n\r\ntop secret body text\r\n";

fn spool_with(count: usize) -> (tempfile::TempDir, FsSpool, Vec<Uuid>) {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = FsSpool::open(dir.path()).expect("spool");
	let ids = (0..count)
		.map(|n| {
			spool
				.store(&AcceptedMessage {
					reverse_path: format!("alice{n}@example.org"),
					recipients: vec![format!("bob{n}@remote.example")],
					data: BODY.as_bytes().to_vec(),
					require_tls: false,
					mailbox: None,
					tlsrpt_verified: false,
					no_dsn: Vec::new(),
				})
				.expect("store")
		})
		.collect();
	(dir, spool, ids)
}

fn run_args(dir: &Path, args: &[&str], now: u64) -> (ExitCode, String) {
	let mut argv = vec!["epistle", "queue"];
	argv.extend(args);
	let cli = Cli::try_parse_from(argv).expect("parse");
	let Command::Queue { action, .. } = cli.command else {
		panic!("not a queue command");
	};
	let mut out = Vec::new();
	let code = run(dir, action, now, &mut out);
	(code, String::from_utf8(out).expect("utf8"))
}

#[test]
fn every_form_parses() {
	let id = Uuid::now_v7().to_string();
	for args in [
		vec!["queue"],
		vec!["queue", "list"],
		vec!["queue", "list", "--json"],
		vec!["queue", "show", &id],
		vec!["queue", "retry", &id],
		vec!["queue", "retry", "--all"],
		vec!["queue", "hold", "--all"],
		vec!["queue", "release", &id],
		vec!["queue", "remove", &id],
		vec!["queue", "--config", "/tmp/x.toml", "list"],
		vec!["queue", "list", "--config", "/tmp/x.toml"],
	] {
		let mut argv = vec!["epistle"];
		argv.extend(args.iter().copied());
		let parsed = Cli::try_parse_from(&argv).unwrap_or_else(|e| panic!("{argv:?}: {e}"));
		assert!(matches!(parsed.command, Command::Queue { .. }), "{argv:?}");
	}
}

#[test]
fn a_target_is_an_id_or_all_but_never_both_or_neither() {
	let id = Uuid::now_v7().to_string();
	for action in ["retry", "hold", "release"] {
		assert!(Cli::try_parse_from(["epistle", "queue", action]).is_err());
		assert!(Cli::try_parse_from(["epistle", "queue", action, &id, "--all"]).is_err());
	}
	assert!(Cli::try_parse_from(["epistle", "queue", "show", "not-a-uuid"]).is_err());
	assert!(Cli::try_parse_from(["epistle", "queue", "remove"]).is_err());
}

#[test]
fn flat_queue_still_lists() {
	let (dir, _spool, ids) = spool_with(2);
	let (code, text) = run_args(dir.path(), &[], 100);
	assert_eq!(code, ExitCode::SUCCESS);
	assert!(text.contains(&format!("{}\tattempts=0\tfrom=alice0@example.org", ids[0])));
	assert!(text.ends_with("2 queued\n"), "{text}");
}

#[test]
fn list_json_has_the_envelope_and_never_the_body() {
	let (dir, spool, ids) = spool_with(2);
	spool
		.record_attempt(ids[0], 500, "connection refused")
		.expect("attempt");
	spool.update_envelope(ids[1], |e| e.hold(5)).expect("hold");
	let (code, text) = run_args(dir.path(), &["list", "--json"], 100);
	assert_eq!(code, ExitCode::SUCCESS);
	assert!(
		!text.contains("secret body"),
		"body leaked into the listing"
	);
	let rows: serde_json::Value = serde_json::from_str(&text).expect("json");
	let rows = rows.as_array().expect("array");
	assert_eq!(rows.len(), 2);
	assert_eq!(rows[0]["id"], ids[0].to_string());
	assert_eq!(rows[0]["attempts"], 1);
	assert_eq!(rows[0]["next_attempt"], 500);
	assert_eq!(rows[0]["held"], false);
	assert_eq!(rows[0]["last_error"], "connection refused");
	assert_eq!(rows[0]["recipients"][0], "bob0@remote.example");
	assert_eq!(rows[1]["held"], true);
	assert_eq!(rows[1]["last_error"], serde_json::Value::Null);
}

#[test]
fn show_prints_envelope_state_and_never_the_body() {
	let (dir, spool, ids) = spool_with(1);
	spool
		.record_attempt(ids[0], 160, "greylisted")
		.expect("attempt");
	let (code, text) = run_args(dir.path(), &["show", &ids[0].to_string()], 100);
	assert_eq!(code, ExitCode::SUCCESS);
	let expected = format!(
		"id: {}\nfrom: alice0@example.org\nto: bob0@remote.example\nattempts: 1\n\
		 next attempt: 160 (in 60s)\nheld: no\nrequire tls: false\nlast error: greylisted\n",
		ids[0]
	);
	assert_eq!(text, expected);
	assert!(!text.contains("secret body"));
}

#[test]
fn show_and_remove_of_an_unknown_id_fail() {
	let (dir, _spool, _ids) = spool_with(1);
	let missing = Uuid::now_v7().to_string();
	for action in ["show", "remove"] {
		let (code, text) = run_args(dir.path(), &[action, &missing], 100);
		assert_eq!(code, ExitCode::FAILURE, "{action}");
		assert_eq!(text, "", "{action}");
	}
}

#[test]
fn retry_makes_the_next_attempt_now_for_one_entry_or_all() {
	let (dir, spool, ids) = spool_with(2);
	for id in &ids {
		spool.record_attempt(*id, 9_999, "down").expect("attempt");
	}
	let (code, text) = run_args(dir.path(), &["retry", &ids[0].to_string()], 100);
	assert_eq!(code, ExitCode::SUCCESS);
	assert_eq!(text, format!("retried {}\n", ids[0]));
	assert_eq!(spool.load_envelope(ids[0]).expect("load").next_attempt, 0);
	assert_eq!(
		spool.load_envelope(ids[1]).expect("load").next_attempt,
		9_999
	);

	let (_, text) = run_args(dir.path(), &["retry", "--all"], 100);
	assert_eq!(text, "retried 2 entries\n");
	assert_eq!(spool.load_envelope(ids[1]).expect("load").next_attempt, 0);
	// A retry resets the backoff only; the attempt count stays.
	assert_eq!(spool.load_envelope(ids[1]).expect("load").attempts, 1);
}

#[test]
fn retry_of_a_held_entry_says_it_is_still_held() {
	let (dir, spool, ids) = spool_with(1);
	spool.update_envelope(ids[0], |e| e.hold(5)).expect("hold");
	let (_, text) = run_args(dir.path(), &["retry", &ids[0].to_string()], 100);
	assert!(text.contains("note: the entry is held"), "{text}");
	assert!(spool.load_envelope(ids[0]).expect("load").held.is_some());
}

#[test]
fn hold_and_release_flip_the_held_state_and_keep_the_held_time() {
	let (dir, spool, ids) = spool_with(2);
	let (code, text) = run_args(dir.path(), &["hold", &ids[0].to_string()], 1_000);
	assert_eq!(
		(code, text.as_str()),
		(ExitCode::SUCCESS, &*format!("held {}\n", ids[0]))
	);
	assert_eq!(spool.load_envelope(ids[0]).expect("load").held, Some(1_000));
	assert_eq!(spool.load_envelope(ids[1]).expect("load").held, None);
	let (_, listing) = run_args(dir.path(), &[], 1_000);
	assert!(
		listing.lines().next().expect("line").ends_with("\theld"),
		"{listing}"
	);

	let (_, text) = run_args(dir.path(), &["hold", "--all"], 2_000);
	assert_eq!(text, "held 2 entries\n");
	assert_eq!(
		spool.load_envelope(ids[0]).expect("load").held,
		Some(1_000),
		"holding twice keeps the first start"
	);
	assert_eq!(spool.load_envelope(ids[1]).expect("load").held, Some(2_000));

	let (_, text) = run_args(dir.path(), &["release", "--all"], 2_500);
	assert_eq!(text, "released 2 entries\n");
	let first = spool.load_envelope(ids[0]).expect("load");
	assert_eq!((first.held, first.held_secs), (None, 1_500));
	let second = spool.load_envelope(ids[1]).expect("load");
	assert_eq!((second.held, second.held_secs), (None, 500));
}

#[test]
fn remove_deletes_the_entry_and_its_body() {
	let (dir, spool, ids) = spool_with(2);
	let (code, text) = run_args(dir.path(), &["remove", &ids[0].to_string()], 100);
	assert_eq!(
		(code, text),
		(ExitCode::SUCCESS, format!("removed {}\n", ids[0]))
	);
	assert_eq!(spool.list().expect("list"), vec![ids[1]]);
	assert!(
		!dir.path()
			.join(format!("spool/new/{}.eml", ids[0]))
			.exists()
	);
}

#[test]
fn all_actions_on_an_empty_queue_report_zero() {
	let dir = tempfile::tempdir().expect("tempdir");
	for (action, line) in [
		("retry", "retried 0 entries\n"),
		("hold", "held 0 entries\n"),
		("release", "released 0 entries\n"),
	] {
		assert_eq!(
			run_args(dir.path(), &[action, "--all"], 100),
			(ExitCode::SUCCESS, line.to_string())
		);
	}
}

#[test]
fn dispatch_reaches_the_spool_named_by_the_config_file() {
	let (dir, spool, ids) = spool_with(1);
	let config = crate::cli::tests_b::config_at(dir.path());
	let path = config.path().to_str().expect("utf8");
	let hold = Cli::try_parse_from([
		"epistle",
		"queue",
		"hold",
		&ids[0].to_string(),
		"--config",
		path,
	])
	.expect("parses");
	assert_eq!(hold.run(), ExitCode::SUCCESS);
	assert!(spool.load_envelope(ids[0]).expect("load").held.is_some());
	let release = Cli::try_parse_from(["epistle", "queue", "--config", path, "release", "--all"])
		.expect("parses");
	assert_eq!(release.run(), ExitCode::SUCCESS);
	assert!(spool.load_envelope(ids[0]).expect("load").held.is_none());
}
