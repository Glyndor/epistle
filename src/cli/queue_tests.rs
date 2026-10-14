//! `epistle queue` actions against temporary spool directories.

use super::*;
use crate::cli::queue::QueueCli;
use crate::cli::{Cli, Command};
use crate::smtp::session::AcceptedMessage;
use clap::Parser;
use std::collections::BTreeMap;

const BODY: &str = "Subject: hi\r\n\r\ntop secret body text\r\n";

fn spool_with(count: usize) -> (tempfile::TempDir, FsSpool, Vec<Uuid>) {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = FsSpool::open(dir.path()).expect("spool");
	let ids = (0..count)
		.map(|n| {
			spool
				.store(
					&AcceptedMessage {
						reverse_path: format!("alice{n}@example.org"),
						recipients: vec![format!("bob{n}@remote.example")],
						data: BODY.as_bytes().to_vec(),
						require_tls: false,
						mailbox: None,
						tlsrpt_verified: false,
						sender_verified: false,
						no_dsn: Vec::new(),
					},
					None,
					&BTreeMap::new(),
				)
				.expect("store")
		})
		.collect();
	(dir, spool, ids)
}

fn run_args(dir: &Path, args: &[&str], now: u64) -> (ExitCode, String) {
	let mut argv = vec!["epistle", "queue"];
	argv.extend(args);
	let cli = Cli::try_parse_from(argv).expect("parse");
	let Command::Queue { mut action, .. } = cli.command else {
		panic!("not a queue command");
	};
	// `queue remove` is destructive; tests drive it non-interactively
	// and need `--yes` to satisfy the confirmation contract. The flag
	// lives on the subcommand variant, not on the queue root.
	if let Some(QueueCli::Remove { ref mut yes, .. }) = action {
		*yes = true;
	}
	let mut out = Vec::new();
	let code = run(dir, 0, action, now, None, &mut out);
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
	// `show` and `remove` of an unknown id both fail; the exit code is
	// the standard `FAILURE` (1) because the confirmation was passed
	// (`--yes` is set by the test harness). The `from(2)` refusal is
	// reserved for the no-confirmation path; it is exercised by
	// `queue_remove_refuses_without_yes`.
	for action in ["show", "remove"] {
		let (code, text) = run_args(dir.path(), &[action, &missing], 100);
		assert_eq!(code, ExitCode::from(2), "{action}");
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

#[test]
fn show_json_prints_one_object_for_the_entry() {
	let (dir, _spool, ids) = spool_with(1);
	let id = ids[0].to_string();
	let (code, text) = run_args(dir.path(), &["show", &id, "--json"], 0);
	assert_eq!(code, ExitCode::SUCCESS);
	let value: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
	assert_eq!(value["id"], serde_json::json!(id));
	assert_eq!(value["reverse_path"], "alice0@example.org");
	assert_eq!(
		value["recipients"],
		serde_json::json!(["bob0@remote.example"])
	);
	assert_eq!(value["held"], false);
	assert_eq!(value["held_since"], serde_json::Value::Null);
	assert_eq!(value["require_tls"], false);
	assert!(
		!text.contains("top secret"),
		"the body leaked into the JSON"
	);
}

#[test]
fn remove_writes_a_canceled_record_for_each_pending_recipient() {
	let (dir, _spool, ids) = spool_with(1);
	let id = ids[0];
	let mut out = Vec::new();
	let code = run(
		dir.path(),
		30,
		Some(QueueCli::Remove { id, yes: true }),
		1_700_000_000,
		None,
		&mut out,
	);
	assert_eq!(code, ExitCode::SUCCESS);
	assert!(
		!dir.path()
			.join("spool/new")
			.join(format!("{id}.json"))
			.exists()
	);

	let log_root = dir.path().join("deliverylog");
	assert!(log_root.is_dir());
	let mut paths: Vec<_> = std::fs::read_dir(&log_root)
		.unwrap()
		.flatten()
		.map(|e| e.path())
		.collect();
	assert_eq!(paths.len(), 1, "one day file");
	let path = paths.pop().unwrap();
	let body = std::fs::read_to_string(&path).unwrap();
	let lines: Vec<&str> = body.lines().collect();
	assert_eq!(lines.len(), 1, "one record per pending recipient");
	let record: crate::storage::DeliveryRecord = serde_json::from_str(lines[0]).expect("record");
	assert_eq!(record.spool_id, id);
	assert_eq!(record.recipient, "bob0@remote.example");
	assert_eq!(record.from, "alice0@example.org");
	assert_eq!(record.outcome, crate::storage::DeliveryOutcome::Canceled);
	assert_eq!(record.time, 1_700_000_000);
	assert_eq!(record.account, None);
}

#[test]
fn remove_with_log_disabled_does_not_write_records() {
	let (dir, _spool, ids) = spool_with(1);
	let id = ids[0];
	let mut out = Vec::new();
	let code = run(
		dir.path(),
		0,
		Some(QueueCli::Remove { id, yes: true }),
		1_700_000_000,
		None,
		&mut out,
	);
	assert_eq!(code, ExitCode::SUCCESS);
	assert!(!dir.path().join("deliverylog").exists());
}

/// Start a webhook receiver; returns its URL and a shared body list.
async fn webhook_receiver() -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
	let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
	async fn handler(
		axum::extract::State(state): axum::extract::State<
			std::sync::Arc<std::sync::Mutex<Vec<String>>>,
		>,
		body: String,
	) -> &'static str {
		state.lock().expect("lock").push(body);
		"ok"
	}
	let app = axum::Router::new()
		.route("/hook", axum::routing::post(handler))
		.with_state(captured.clone());
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
		.await
		.expect("bind");
	let addr = listener.local_addr().expect("addr");
	tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });
	(format!("http://{addr}/hook"), captured)
}

#[tokio::test]
async fn remove_emits_a_canceled_webhook_for_each_pending_recipient() {
	let (url, captured) = webhook_receiver().await;
	let (dir, _spool, ids) = spool_with(1);
	let id = ids[0];
	let webhook = std::sync::Arc::new(crate::webhook::Webhook::new(&url, None).expect("webhook"));
	let mut out = Vec::new();
	let code = run(
		dir.path(),
		30,
		Some(QueueCli::Remove { id, yes: true }),
		1_700_000_000,
		Some(&webhook),
		&mut out,
	);
	assert_eq!(code, ExitCode::SUCCESS);
	for _ in 0..200 {
		if !captured.lock().expect("lock").is_empty() {
			break;
		}
		tokio::time::sleep(std::time::Duration::from_millis(10)).await;
	}
	let bodies = captured.lock().expect("lock").clone();
	let body = bodies
		.iter()
		.find(|body| body.contains("\"event\":\"canceled\""))
		.expect("a canceled body");
	let event: serde_json::Value = serde_json::from_str(body).expect("json");
	assert_eq!(event["spool_id"], id.to_string());
	assert_eq!(event["recipient"], "bob0@remote.example");
}
