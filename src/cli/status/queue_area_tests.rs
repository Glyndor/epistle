//! Tests for the queue check with hand-written spool entries whose ids are
//! UUID v7 values minted at chosen times.

use std::collections::BTreeMap;
use std::path::Path;

use uuid::{Timestamp, Uuid};

use super::evaluate;
use crate::cli::status::report::Level;
use crate::storage::Envelope;

const NOW: i64 = 1_791_532_800;

/// Write one spool entry enqueued `age` seconds before `NOW`.
fn enqueue(data_dir: &Path, age: i64, attempts: u32, next_attempt: u64) -> Uuid {
	let secs = u64::try_from(NOW - age).expect("positive");
	let id = Uuid::new_v7(Timestamp::from_unix(uuid::NoContext, secs, 0));
	let new = data_dir.join("spool").join("new");
	std::fs::create_dir_all(&new).expect("spool dir");
	let envelope = Envelope {
		id,
		reverse_path: "alice@example.org".into(),
		recipients: vec!["bob@example.net".into()],
		attempts,
		next_attempt,
		require_tls: false,
		no_dsn: Vec::new(),
		delay_warned: false,
		held: None,
		held_secs: 0,
		last_error: None,
		recipient_state: Default::default(),
		account: None,
		extra: BTreeMap::new(),
		class: Default::default(),
		evidence: false,
		retain_days: 0,
		outcomes_pending: Vec::new(),
	};
	std::fs::write(
		new.join(format!("{id}.json")),
		serde_json::to_vec(&envelope).expect("json"),
	)
	.expect("envelope");
	std::fs::write(new.join(format!("{id}.eml")), b"Subject: x\r\n\r\nbody\r\n").expect("message");
	id
}

#[test]
fn an_empty_or_missing_spool_is_ok_and_is_not_created() {
	let dir = tempfile::tempdir().expect("tempdir");
	let report = evaluate(dir.path(), None, NOW);
	assert_eq!(report.status, Level::Ok);
	assert_eq!(report.detail, "0 messages queued (no spool yet)");
	assert!(
		!dir.path().join("spool").exists(),
		"the check must not create the spool"
	);
}

#[test]
fn counts_messages_and_deferrals_and_reports_the_oldest() {
	let dir = tempfile::tempdir().expect("tempdir");
	enqueue(dir.path(), 600, 0, 0);
	enqueue(
		dir.path(),
		1800,
		2,
		u64::try_from(NOW + 300).expect("future"),
	);
	enqueue(dir.path(), 900, 0, u64::try_from(NOW + 60).expect("future"));
	let report = evaluate(dir.path(), None, NOW);
	assert_eq!(report.status, Level::Ok, "{report:?}");
	assert_eq!(report.detail, "3 queued, oldest 30m, 2 deferred");
	assert_eq!(report.items[0].detail, "3 queued, 2 deferred");
}

#[test]
fn the_age_thresholds_are_over_4_hours_for_warn_and_over_24_for_fail() {
	for (age, expected) in [
		(4 * 3600 - 1, Level::Ok),
		(4 * 3600, Level::Ok),
		(4 * 3600 + 1, Level::Warn),
		(24 * 3600, Level::Warn),
		(24 * 3600 + 1, Level::Fail),
	] {
		let dir = tempfile::tempdir().expect("tempdir");
		enqueue(dir.path(), age, 0, 0);
		enqueue(dir.path(), 10, 0, 0);
		let report = evaluate(dir.path(), None, NOW);
		assert_eq!(report.status, expected, "oldest {age}s: {report:?}");
	}
}

#[test]
fn only_the_oldest_message_decides_the_age() {
	let dir = tempfile::tempdir().expect("tempdir");
	enqueue(dir.path(), 5 * 3600, 3, 0);
	enqueue(dir.path(), 60, 0, 0);
	let report = evaluate(dir.path(), None, NOW);
	assert_eq!(report.status, Level::Warn, "{report:?}");
	assert_eq!(report.items[1].detail, "oldest message is 5h0m old");
}

#[test]
fn an_unreadable_entry_warns_and_does_not_hide_the_rest() {
	let dir = tempfile::tempdir().expect("tempdir");
	enqueue(dir.path(), 60, 0, 0);
	let broken = enqueue(dir.path(), 30, 0, 0);
	std::fs::write(
		dir.path().join("spool/new").join(format!("{broken}.json")),
		b"{not json",
	)
	.expect("corrupt");
	let report = evaluate(dir.path(), None, NOW);
	assert_eq!(report.status, Level::Warn, "{report:?}");
	assert_eq!(report.items[0].detail, "2 queued, 0 deferred");
	assert_eq!(report.items[1].detail, "1 spool entries could not be read");
}

#[test]
fn the_envelope_is_read_without_the_message_body() {
	let dir = tempfile::tempdir().expect("tempdir");
	let id = enqueue(dir.path(), 60, 0, 0);
	std::fs::remove_file(dir.path().join("spool/new").join(format!("{id}.eml"))).expect("rm body");
	let report = evaluate(dir.path(), None, NOW);
	assert_eq!(
		report.detail, "1 queued, oldest 1m, 0 deferred",
		"{report:?}"
	);
	assert_eq!(report.status, Level::Ok);
}

/// A message the operator put on hold is deliberate: it is counted as held
/// and its age does not turn the check red.
#[test]
fn a_held_message_is_counted_and_does_not_decide_the_age() {
	let dir = tempfile::tempdir().expect("tempdir");
	let held = enqueue(dir.path(), 3 * 24 * 3600, 2, 0);
	enqueue(dir.path(), 60, 0, 0);
	let spool = crate::storage::FsSpool::open(dir.path()).expect("spool");
	spool
		.update_envelope(held, |envelope| envelope.hold(1))
		.expect("hold");
	let report = evaluate(dir.path(), None, NOW);
	assert_eq!(report.status, Level::Ok, "{report:?}");
	assert!(report.detail.contains("1 held"), "{report:?}");
}

/// With `encrypt_at_rest` on, the check reads sealed envelopes with the
/// configured key instead of counting every entry as unreadable.
#[test]
fn sealed_envelopes_are_read_with_the_configured_key() {
	let dir = tempfile::tempdir().expect("tempdir");
	let key_file = dir.path().join("mail.key");
	std::fs::write(
		&key_file,
		crate::storage::generate_key_base64().expect("keygen"),
	)
	.expect("key file");
	let storage = crate::config::Storage {
		encrypt_at_rest: true,
		encryption_key_env: None,
		encryption_key_file: Some(key_file),
		deleted_retention_days: 0,
		delivery_log_days: 0,
		blobs: None,
	};
	let crypto = crate::storage::MessageCrypto::from_config(Some(&storage)).expect("crypto");
	crate::storage::FsSpool::open_with_crypto(dir.path(), crypto)
		.expect("spool")
		.store(
			&crate::smtp::session::AcceptedMessage {
				reverse_path: "alice@example.org".into(),
				recipients: vec!["bob@example.net".into()],
				data: b"Subject: x\r\n\r\nbody\r\n".to_vec(),
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

	let report = evaluate(dir.path(), Some(&storage), NOW);
	assert!(
		report.items.iter().all(|item| item.name != "entries"),
		"a sealed entry must not be reported unreadable: {report:?}"
	);
}

#[test]
fn mail_waiting_for_the_warm_up_cap_is_not_stuck() {
	let dir = tempfile::tempdir().expect("tempdir");
	let id = enqueue(dir.path(), 3 * 86_400, 0, 0);
	let path = dir
		.path()
		.join("spool")
		.join("new")
		.join(format!("{id}.json"));
	let mut envelope: Envelope =
		serde_json::from_slice(&std::fs::read(&path).expect("read")).expect("parse");
	let mut state = envelope.recipient_state("bob@example.net");
	state.wait_for_cap("gmail", NOW as u64 + 600, NOW as u64 - 3 * 86_400);
	envelope.set_recipient_state("bob@example.net", state);
	std::fs::write(&path, serde_json::to_vec(&envelope).expect("json")).expect("write");
	let report = evaluate(dir.path(), None, NOW);
	assert_eq!(
		(report.status, report.detail.as_str()),
		(
			Level::Ok,
			"1 queued, 0 deferred, 1 waiting for the warm-up cap"
		)
	);
}
