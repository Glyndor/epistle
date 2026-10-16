//! `epistle suppression list` says when and why an address was suppressed.

use super::*;
use crate::queue::test_remote::{FakeRemote, Script};
use crate::smtp::session::AcceptedMessage;
use std::collections::BTreeMap;

fn config(data_dir: &std::path::Path) -> Config {
	let toml = format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"{}\"\n",
		data_dir.display()
	);
	toml::from_str(&toml).expect("config parses")
}

/// Send one message from alice@example.org to carol@remote.example, whose
/// exchanger answers `reply` to RCPT TO.
async fn refused_with(data_dir: &std::path::Path, reply: &str) {
	let spool = crate::storage::FsSpool::open(data_dir).expect("spool");
	spool
		.store(
			&AcceptedMessage {
				reverse_path: "alice@example.org".into(),
				recipients: vec!["carol@remote.example".to_string()],
				data: b"Subject: hi\r\n\r\nbody\r\n".to_vec(),
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
	let remote = FakeRemote::default();
	remote.script(
		"remote.example",
		Script::rcpt("carol@remote.example", reply),
	);
	let worker = crate::queue::Worker::new(spool, std::sync::Arc::new(remote), "mail.example.org")
		.with_suppression(SuppressionList::open(data_dir).expect("open"));
	worker.pass().await.expect("pass");
}

#[tokio::test]
async fn the_list_gives_the_date_and_the_reply_of_a_hard_bounce() {
	let dir = tempfile::tempdir().expect("tempdir");
	refused_with(dir.path(), "550 5.1.1 no such user").await;

	let mut out = Vec::new();
	assert_eq!(
		list(&config(dir.path()), None, false, &mut out),
		ExitCode::SUCCESS
	);
	let out = String::from_utf8(out).expect("utf8");
	let fields: Vec<&str> = out.trim_end().split('\t').collect();
	assert_eq!(
		fields.len(),
		3,
		"address, date and reason, tab separated: {out:?}"
	);
	assert_eq!(fields[0], "carol@remote.example");
	assert!(
		fields[1].len() == 20 && fields[1].ends_with('Z'),
		"RFC 3339 date: {:?}",
		fields[1]
	);
	assert_eq!(fields[2], "550 5.1.1 no such user");

	let mut out = Vec::new();
	list(
		&config(dir.path()),
		Some("alice@example.org"),
		true,
		&mut out,
	);
	let value: serde_json::Value = serde_json::from_slice(&out).expect("json");
	assert_eq!(value[0]["address"], "carol@remote.example");
	assert_eq!(value[0]["account"], "alice@example.org");
	assert_eq!(value[0]["reason"], "550 5.1.1 no such user");
	assert_eq!(value[0]["since"], fields[1]);
}

#[test]
fn an_address_without_a_recorded_reason_lists_alone() {
	let dir = tempfile::tempdir().expect("tempdir");
	// A marker written before reasons were recorded holds the address only.
	SuppressionList::open(dir.path())
		.expect("open")
		.suppress("bob@example.net");

	let mut out = Vec::new();
	list(&config(dir.path()), None, false, &mut out);
	assert_eq!(String::from_utf8(out).expect("utf8"), "bob@example.net\n");
}

#[test]
fn an_address_added_by_hand_says_so() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path());
	add(&config, "bob@example.net", None, false, &mut Vec::new());

	let mut out = Vec::new();
	list(&config, None, false, &mut out);
	let out = String::from_utf8(out).expect("utf8");
	let fields: Vec<&str> = out.trim_end().split('\t').collect();
	assert_eq!(fields.len(), 3, "{out:?}");
	assert_eq!(fields[2], "added by hand (epistle suppression add)");
}
