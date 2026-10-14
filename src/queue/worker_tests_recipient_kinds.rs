//! The queue treats every envelope recipient alike, whatever put it on the
//! envelope: a To, Cc or Bcc address, a Resent-To, Resent-Cc or Resent-Bcc
//! one, an address given only in `RCPT TO`, the target an alias or a
//! catch-all expanded to, and a forward (queued as a message of its own).
//! The queue only sees addresses, so this pins that none of them is
//! special: each is delivered exactly once, with one per-recipient state
//! and one delivery log record of each outcome, and the Bcc and Resent-Bcc
//! fields the submission server stripped never reach a remote.

use std::collections::BTreeMap;

use super::*;
use crate::queue::test_remote::{FakeRemote, Script};
use crate::smtp::session::AcceptedMessage;
use crate::storage::{DeliveryLog, DeliveryOutcome, RecipientStatus};

const SENDER: &str = "alice@sender.example";

/// Every recipient of the submitted message, by what put it there.
const KINDS: [(&str, &str); 9] = [
	("To", "to@one.example"),
	("Cc", "cc@two.example"),
	("Bcc", "bcc@one.example"),
	("Resent-To", "resent-to@two.example"),
	("Resent-Cc", "resent-cc@one.example"),
	("Resent-Bcc", "resent-bcc@two.example"),
	("envelope only", "envelope@one.example"),
	("alias expansion", "alias-target@two.example"),
	("catch-all", "catch-all-target@one.example"),
];
const FORWARD: &str = "forward-target@two.example";

const SUBMITTED: &str = "From: alice@sender.example\r\n\
	To: to@one.example\r\n\
	Cc: cc@two.example\r\n\
	Bcc: bcc@one.example\r\n\
	Resent-From: alice@sender.example\r\n\
	Resent-To: resent-to@two.example\r\n\
	Resent-Cc: resent-cc@one.example\r\n\
	Resent-Bcc: resent-bcc@two.example\r\n\
	Subject: every kind\r\n\
	\r\n\
	body\r\n";

fn message(recipients: Vec<String>, data: Vec<u8>, reverse_path: &str) -> AcceptedMessage {
	AcceptedMessage {
		reverse_path: reverse_path.into(),
		recipients,
		data,
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		no_dsn: Vec::new(),
	}
}

#[tokio::test]
async fn every_kind_of_recipient_is_delivered_once_and_alike() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = FsSpool::open(dir.path()).expect("open spool");
	// What the submission server queues: Bcc and Resent-Bcc stripped, the
	// addresses on the envelope.
	let data = crate::smtp::trace::strip_bcc(SUBMITTED.as_bytes());
	let recipients: Vec<String> = KINDS
		.iter()
		.map(|(_, address)| address.to_string())
		.collect();
	let main = spool
		.store(
			&message(recipients, data.clone(), SENDER),
			None,
			&BTreeMap::new(),
		)
		.expect("store");
	let forwarded = [b"Delivered-To: bob@sender.example\r\n".as_slice(), &data].concat();
	spool
		.store(
			&message(vec![FORWARD.into()], forwarded, "forwarder@sender.example"),
			None,
			&BTreeMap::new(),
		)
		.expect("store forward");
	let remote = FakeRemote::default();
	let busy = Script {
		greeting: Some("451 4.3.0 try again later".into()),
		..Script::default()
	};
	remote.script("two.example", busy);
	let mut worker = Worker::new(spool, Arc::new(remote.clone()), "mail.sender.example")
		.with_delivery_log(DeliveryLog::open(dir.path(), 30));
	worker.set_jitter(|| 1.0);
	let start = main.get_timestamp().expect("v7").to_unix().0 + 1;
	worker.set_now(start);

	// First pass: one.example takes its recipients, two.example defers.
	worker.pass().await.expect("pass");
	let envelope = worker.spool.load_envelope(main).expect("envelope");
	assert_eq!(
		envelope.recipient_state.keys().collect::<Vec<_>>().len(),
		KINDS.len(),
		"one state per recipient"
	);
	for (kind, address) in KINDS {
		let state = envelope.recipient_state(address);
		let expected = match address.ends_with("@one.example") {
			true => (RecipientStatus::Delivered, 0),
			false => (RecipientStatus::Pending, 1),
		};
		assert_eq!((state.status, state.attempts), expected, "{kind}");
	}

	// Second pass: two.example takes the rest.
	remote.script("two.example", Script::default());
	worker.set_now(start + 3600);
	worker.pass().await.expect("pass");
	assert!(worker.spool.list().expect("list").is_empty());

	let all = KINDS.iter().map(|(_, address)| *address).chain([FORWARD]);
	for address in all.clone() {
		assert_eq!(remote.copies(address), 1, "{address}");
	}
	let messages = remote.messages();
	assert_eq!(messages.len(), 3, "one.example, two.example, the forward");
	for text in &messages {
		let lower = text.to_ascii_lowercase();
		for field in [
			"to: to@one.example",
			"cc: cc@two.example",
			"resent-to: resent-to@two.example",
			"resent-cc: resent-cc@one.example",
		] {
			assert!(lower.contains(field), "{field} missing");
		}
		assert!(!lower.contains("bcc:"), "a Bcc field reached a remote");
		assert!(
			!lower.contains("bcc@one.example"),
			"a Bcc address reached a remote"
		);
		assert!(
			!lower.contains("resent-bcc@two.example"),
			"a Resent-Bcc address reached a remote"
		);
	}

	let log = DeliveryLog::open(dir.path(), 30)
		.list(None, |_| true)
		.expect("log");
	for address in all {
		let outcomes: Vec<DeliveryOutcome> = log
			.iter()
			.filter(|record| record.recipient == address)
			.map(|record| record.outcome)
			.collect();
		let expected = match address.ends_with("@two.example") {
			true => vec![DeliveryOutcome::Deferred, DeliveryOutcome::Delivered],
			false => vec![DeliveryOutcome::Delivered],
		};
		let mut sorted = outcomes.clone();
		sorted.sort_by_key(|outcome| outcome.as_str() != "deferred");
		assert_eq!(sorted, expected, "{address}");
	}
}
