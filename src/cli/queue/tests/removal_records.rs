//! `epistle queue remove` writes canceled records and webhooks, and sealed envelopes are read.

use super::*;
use crate::cli::queue::QueueCli;
use crate::cli::{Cli, Command};
use crate::smtp::session::AcceptedMessage;
use clap::Parser;
use std::collections::BTreeMap;

use super::base::*;

#[test]
fn remove_writes_a_canceled_record_for_each_pending_recipient() {
	let (dir, _spool, ids) = spool_with(1);
	let id = ids[0];
	let mut out = Vec::new();
	let code = run(
		dir.path(),
		None,
		30,
		Some(QueueCli::Remove { id, yes: true }),
		false,
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
		None,
		0,
		Some(QueueCli::Remove { id, yes: true }),
		false,
		1_700_000_000,
		None,
		&mut out,
	);
	assert_eq!(code, ExitCode::SUCCESS);
	assert!(!dir.path().join("deliverylog").exists());
}

/// Start a webhook receiver; returns its URL and a shared body list.
pub(super) async fn webhook_receiver() -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
	crate::webhook::tests::receiver::webhook_receiver().await
}

#[tokio::test]
async fn remove_emits_a_canceled_webhook_for_each_pending_recipient() {
	let (url, captured) = webhook_receiver().await;
	let (dir, _spool, ids) = spool_with(1);
	let id = ids[0];
	let webhook = std::sync::Arc::new(
		crate::webhook::Webhook::new_allowing_private(&url, None).expect("webhook"),
	);
	let mut out = Vec::new();
	let code = run(
		dir.path(),
		None,
		30,
		Some(QueueCli::Remove { id, yes: true }),
		false,
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

/// With `encrypt_at_rest` on every envelope is sealed, so the operator
/// commands must open the spool with the configured key. A listing that
/// cannot read an envelope prints no row for it, and `show` fails outright.
#[test]
fn queue_commands_read_sealed_envelopes_with_the_configured_key() {
	let dir = tempfile::tempdir().expect("tempdir");
	let key_file = dir.path().join("mail.key");
	std::fs::write(
		&key_file,
		crate::storage::generate_key_base64().expect("keygen"),
	)
	.expect("key file");
	let storage = crate::config::Storage {
		encrypt_at_rest: true,
		tenant_keys: false,
		retired_key_files: Vec::new(),
		encryption_key_env: None,
		encryption_key_file: Some(key_file),
		deleted_retention_days: 0,
		delivery_log_days: 0,
		blobs: None,
	};
	let crypto = crate::storage::MessageCrypto::from_config(Some(&storage)).expect("crypto");
	let id = FsSpool::open_with_crypto(dir.path(), crypto)
		.expect("spool")
		.store(
			&AcceptedMessage {
				reverse_path: "sealed@example.org".into(),
				recipients: vec!["bob@remote.example".into()],
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
		.expect("store");

	let mut out = Vec::new();
	assert_eq!(
		list(dir.path(), Some(&storage), &mut out),
		ExitCode::SUCCESS
	);
	let listed = String::from_utf8(out).expect("utf8");
	assert!(
		listed.contains(&id.to_string()) && listed.contains("sealed@example.org"),
		"the sealed entry must be listed: {listed}"
	);

	let mut out = Vec::new();
	let code = run(
		dir.path(),
		Some(&storage),
		0,
		Some(QueueCli::Show { id, json: false }),
		false,
		1_700_000_000,
		None,
		&mut out,
	);
	assert_eq!(
		code,
		ExitCode::SUCCESS,
		"show must read the sealed envelope"
	);
}

/// `run_args` with `--json`: the exit code and the one object printed.
pub(super) fn run_json(dir: &Path, args: &[&str], now: u64) -> (ExitCode, serde_json::Value) {
	let mut argv = vec!["epistle", "queue"];
	argv.extend(args);
	let cli = Cli::try_parse_from(argv).expect("parse");
	let Command::Queue { action, .. } = cli.command else {
		panic!("not a queue command");
	};
	let mut out = Vec::new();
	let code = run(dir, None, 0, action, true, now, None, &mut out);
	let text = String::from_utf8(out).expect("utf8");
	assert_eq!(text.lines().count(), 1, "not one line of JSON: {text}");
	(code, serde_json::from_str(&text).expect("json"))
}
