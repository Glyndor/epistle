//! Tests for admin-configured external forwarding (account-level redirects).

use super::*;

fn directory_with_forward(targets: Vec<String>, keep_local: bool) -> DirectoryHandle {
	DirectoryHandle::new(
		crate::smtp::directory::Directory::new(
			["example.org".to_string()],
			[("alice@example.org".to_string(), "alice".to_string())],
		)
		.with_forwards([("alice".to_string(), (targets, keep_local))]),
	)
}

fn message_from(sender: &str, data: &[u8]) -> AcceptedMessage {
	AcceptedMessage {
		reverse_path: sender.into(),
		recipients: vec!["alice@example.org".to_string()],
		data: data.to_vec(),
		require_tls: false,
		mailbox: None,
		no_dsn: Vec::new(),
	}
}

fn inbox_count(root: &std::path::Path, account: &str) -> usize {
	fs::read_dir(root.join("accounts").join(account).join("new"))
		.map(|entries| entries.count())
		.unwrap_or(0)
}

const BODY: &[u8] = b"Subject: hi\r\n\r\nbody\r\n";

#[test]
fn forwards_and_keeps_local_copy() {
	let dir = tempfile::tempdir().expect("tempdir");
	let delivery = LocalDelivery::new(
		dir.path(),
		directory_with_forward(vec!["ext@other.example".to_string()], true),
	)
	.expect("delivery");
	let out = delivery
		.deliver_routed(&message_from("s@x.example", BODY), None)
		.expect("deliver");
	assert_eq!(out.redirects, vec!["ext@other.example".to_string()]);
	// keep_local = true keeps the INBOX copy.
	assert_eq!(inbox_count(dir.path(), "alice"), 1);
}

#[test]
fn pure_forward_skips_local_copy() {
	let dir = tempfile::tempdir().expect("tempdir");
	let delivery = LocalDelivery::new(
		dir.path(),
		directory_with_forward(vec!["ext@other.example".to_string()], false),
	)
	.expect("delivery");
	let out = delivery
		.deliver_routed(&message_from("s@x.example", BODY), None)
		.expect("deliver");
	assert_eq!(out.redirects, vec!["ext@other.example".to_string()]);
	// keep_local = false stores no local copy (pure forwarding).
	assert_eq!(inbox_count(dir.path(), "alice"), 0);
}

#[test]
fn never_forwards_a_bounce() {
	let dir = tempfile::tempdir().expect("tempdir");
	let delivery = LocalDelivery::new(
		dir.path(),
		directory_with_forward(vec!["ext@other.example".to_string()], false),
	)
	.expect("delivery");
	// Null reverse-path (a bounce): never forward (loop risk); deliver locally.
	let out = delivery
		.deliver_routed(&message_from("", BODY), None)
		.expect("deliver");
	assert!(out.redirects.is_empty());
	assert_eq!(inbox_count(dir.path(), "alice"), 1);
}

#[test]
fn stops_a_looping_message() {
	let dir = tempfile::tempdir().expect("tempdir");
	let delivery = LocalDelivery::new(
		dir.path(),
		directory_with_forward(vec!["ext@other.example".to_string()], false),
	)
	.expect("delivery");
	// A message that has already crossed too many hops is not forwarded.
	let mut data = Vec::new();
	for _ in 0..(MAX_FORWARD_HOPS + 1) {
		data.extend_from_slice(b"Received: from a by b\r\n");
	}
	data.extend_from_slice(b"Subject: loop\r\n\r\nbody\r\n");
	let out = delivery
		.deliver_routed(&message_from("s@x.example", &data), None)
		.expect("deliver");
	assert!(out.redirects.is_empty(), "looping message must not forward");
	// keep_local=false but the loop guard fired, so it is delivered locally
	// rather than dropped (fail safe).
	assert_eq!(inbox_count(dir.path(), "alice"), 1);
}

#[test]
fn counts_received_hops() {
	assert_eq!(received_hops(b"Subject: x\r\n\r\nbody"), 0);
	assert_eq!(
		received_hops(b"Received: a\r\nReceived: b\r\nSubject: x\r\n\r\nbody"),
		2
	);
	// Received tokens in the body are not counted.
	assert_eq!(received_hops(b"Subject: x\r\n\r\nReceived: nope"), 0);
}

#[test]
fn multi_target_alias_delivers_to_every_member() {
	let dir = tempfile::tempdir().expect("tempdir");
	let directory = DirectoryHandle::new(
		crate::smtp::directory::Directory::new(
			["example.org".to_string()],
			[
				("alice@example.org".to_string(), "alice".to_string()),
				("bob@example.org".to_string(), "bob".to_string()),
			],
		)
		.with_aliases([(
			"team@example.org".to_string(),
			crate::smtp::directory::AliasSpec {
				members: vec![
					"alice@example.org".to_string(),
					"bob@example.org".to_string(),
				],
				senders: Vec::new(),
				hidden: true,
			},
		)]),
	);
	let delivery = LocalDelivery::new(dir.path(), directory).expect("delivery");
	let message = AcceptedMessage {
		reverse_path: "sender@elsewhere.example".into(),
		recipients: vec!["team@example.org".to_string()],
		data: BODY.to_vec(),
		require_tls: false,
		mailbox: None,
		no_dsn: Vec::new(),
	};
	delivery.deliver(message).expect("deliver to alias");
	// Both members received exactly one copy.
	assert_eq!(inbox_count(dir.path(), "alice"), 1);
	assert_eq!(inbox_count(dir.path(), "bob"), 1);
}
