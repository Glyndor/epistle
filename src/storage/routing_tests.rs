//! Tests for delivery routing (SplitDelivery).

use super::*;
use std::fs;

fn directory() -> DirectoryHandle {
	DirectoryHandle::new(crate::smtp::directory::Directory::new(
		["example.org".to_string()],
		[("alice@example.org".to_string(), "alice".to_string())],
	))
}

fn message(recipients: &[&str]) -> AcceptedMessage {
	AcceptedMessage {
		reverse_path: "alice@example.org".into(),
		recipients: recipients.iter().map(|r| r.to_string()).collect(),
		data: b"Subject: hi\r\n\r\nbody\r\n".to_vec(),
		require_tls: false,
		mailbox: None,
	}
}

fn inbox_count(root: &std::path::Path, account: &str) -> usize {
	fs::read_dir(root.join("accounts").join(account).join("new"))
		.map(|entries| entries.count())
		.unwrap_or(0)
}

fn spool_count(root: &std::path::Path) -> usize {
	FsSpool::open(root)
		.expect("open spool")
		.list()
		.expect("list")
		.len()
}

fn folder_count(root: &std::path::Path, account: &str, mailbox: &str) -> usize {
	fs::read_dir(
		root.join("accounts")
			.join(account)
			.join("folders")
			.join(mailbox)
			.join("new"),
	)
	.map(|entries| entries.count())
	.unwrap_or(0)
}

#[test]
fn junk_rule_files_into_the_junk_mailbox() {
	let dir = tempfile::tempdir().expect("tempdir");
	let rule = crate::rules::Rule {
		sender_domain: Some("example.org".to_string()),
		header: None,
		header_contains: None,
		junk: true,
		mailbox: None,
	};
	let sink = SplitDelivery::new(dir.path(), directory())
		.expect("sink")
		.with_rules(vec![rule]);
	sink.deliver(message(&["alice@example.org"]))
		.expect("deliver");
	// Routed to Junk, not INBOX.
	assert_eq!(folder_count(dir.path(), "alice", "Junk"), 1);
	assert_eq!(inbox_count(dir.path(), "alice"), 0);
}

#[test]
fn explicit_mailbox_hint_quarantines_to_that_folder() {
	let dir = tempfile::tempdir().expect("tempdir");
	let sink = SplitDelivery::new(dir.path(), directory()).expect("sink");
	let mut msg = message(&["alice@example.org"]);
	msg.mailbox = Some("Rejects".to_string());
	sink.deliver(msg).expect("deliver");
	assert_eq!(folder_count(dir.path(), "alice", "Rejects"), 1);
	assert_eq!(inbox_count(dir.path(), "alice"), 0);
}

#[test]
fn sieve_reject_bounces_and_skips_delivery() {
	let dir = tempfile::tempdir().expect("tempdir");
	let account_dir = dir.path().join("accounts").join("alice");
	fs::create_dir_all(&account_dir).expect("mkdir");
	fs::write(account_dir.join("filter.sieve"), "reject \"no thanks\";").expect("filter");
	let sink = SplitDelivery::new(dir.path(), directory()).expect("sink");
	sink.deliver(message(&["alice@example.org"]))
		.expect("deliver");
	// Rejected: nothing delivered, one DSN bounce queued to the sender.
	assert_eq!(inbox_count(dir.path(), "alice"), 0);
	let spool = FsSpool::open(dir.path()).expect("spool");
	let ids = spool.list().expect("list");
	assert_eq!(ids.len(), 1);
	let entry = spool.load(ids[0]).expect("load");
	// A DSN uses the null reverse-path and goes to the original sender.
	assert!(
		entry.envelope.reverse_path.is_empty(),
		"{:?}",
		entry.envelope
	);
	assert_eq!(
		entry.envelope.recipients,
		vec!["alice@example.org".to_string()]
	);
}

#[test]
fn sieve_vacation_replies_once_and_keeps() {
	let dir = tempfile::tempdir().expect("tempdir");
	let account_dir = dir.path().join("accounts").join("alice");
	fs::create_dir_all(&account_dir).expect("mkdir");
	fs::write(account_dir.join("filter.sieve"), "vacation \"I am away\";").expect("filter");
	let sink = SplitDelivery::new(dir.path(), directory()).expect("sink");

	let mut msg = message(&["alice@example.org"]);
	msg.reverse_path = "bob@example.net".into();
	sink.deliver(msg).expect("deliver");
	// Kept in INBOX, one null-sender autoresponse queued to the sender.
	assert_eq!(inbox_count(dir.path(), "alice"), 1);
	let spool = FsSpool::open(dir.path()).expect("spool");
	let ids = spool.list().expect("list");
	assert_eq!(ids.len(), 1);
	let reply = spool.load(ids[0]).expect("load");
	assert!(reply.envelope.reverse_path.is_empty(), "null sender");
	assert_eq!(
		reply.envelope.recipients,
		vec!["bob@example.net".to_string()]
	);

	// A second message from the same sender is deduped: no new reply.
	let mut again = message(&["alice@example.org"]);
	again.reverse_path = "bob@example.net".into();
	sink.deliver(again).expect("deliver");
	assert_eq!(spool.list().expect("list").len(), 1);
}

#[test]
fn sieve_redirect_queues_to_the_spool() {
	let dir = tempfile::tempdir().expect("tempdir");
	let account_dir = dir.path().join("accounts").join("alice");
	fs::create_dir_all(&account_dir).expect("mkdir");
	fs::write(
		account_dir.join("filter.sieve"),
		"redirect \"forward@example.com\";",
	)
	.expect("filter");
	let sink = SplitDelivery::new(dir.path(), directory()).expect("sink");
	sink.deliver(message(&["alice@example.org"]))
		.expect("deliver");
	// Redirect cancels the implicit keep: nothing in INBOX, one in the spool.
	assert_eq!(inbox_count(dir.path(), "alice"), 0);
	let spool = FsSpool::open(dir.path()).expect("spool");
	let ids = spool.list().expect("list");
	assert_eq!(ids.len(), 1);
	let entry = spool.load(ids[0]).expect("load");
	assert_eq!(
		entry.envelope.recipients,
		vec!["forward@example.com".to_string()]
	);
}

#[test]
fn srs_rewrites_the_forwarded_sender() {
	let dir = tempfile::tempdir().expect("tempdir");
	let account_dir = dir.path().join("accounts").join("alice");
	fs::create_dir_all(&account_dir).expect("mkdir");
	fs::write(
		account_dir.join("filter.sieve"),
		"redirect \"forward@example.com\";",
	)
	.expect("filter");
	let srs = crate::queue::srs::Srs::new(b"test secret");
	let sink = SplitDelivery::new(dir.path(), directory())
		.expect("sink")
		.with_srs(srs, "relay.example");
	sink.deliver(message(&["alice@example.org"]))
		.expect("deliver");
	let spool = FsSpool::open(dir.path()).expect("spool");
	let ids = spool.list().expect("list");
	let entry = spool.load(ids[0]).expect("load");
	// The forwarded sender is rewritten to an SRS address at our domain.
	assert!(
		entry.envelope.reverse_path.starts_with("SRS0="),
		"{}",
		entry.envelope.reverse_path
	);
	assert!(entry.envelope.reverse_path.ends_with("@relay.example"));
}

#[test]
fn srs_return_address_forwards_to_original_sender() {
	let dir = tempfile::tempdir().expect("tempdir");
	let srs = crate::queue::srs::Srs::new(b"test secret");
	// Encode an SRS-return address for the original sender at our domain.
	let now_days = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs() / 86_400)
		.unwrap_or(0);
	let srs_local = srs
		.forward("origsender", "origin.example", "relay.example", now_days)
		.split_once('@')
		.unwrap()
		.0
		.to_string();
	let sink = SplitDelivery::new(dir.path(), directory())
		.expect("sink")
		.with_srs(crate::queue::srs::Srs::new(b"test secret"), "relay.example");

	let bounce = AcceptedMessage {
		reverse_path: String::new(),
		recipients: vec![format!("{srs_local}@relay.example")],
		data: b"Subject: bounce\r\n\r\nfailed\r\n".to_vec(),
		require_tls: false,
		mailbox: None,
	};
	sink.deliver(bounce).expect("deliver");
	// The bounce is re-queued to the original sender it encoded.
	let spool = FsSpool::open(dir.path()).expect("spool");
	let ids = spool.list().expect("list");
	assert_eq!(ids.len(), 1);
	let entry = spool.load(ids[0]).expect("load");
	assert_eq!(
		entry.envelope.recipients,
		vec!["origsender@origin.example".to_string()]
	);
}

#[test]
fn local_only_message_skips_the_spool() {
	let dir = tempfile::tempdir().expect("tempdir");
	let sink = SplitDelivery::new(dir.path(), directory()).expect("sink");
	sink.deliver(message(&["alice@example.org"]))
		.expect("deliver");
	assert_eq!(inbox_count(dir.path(), "alice"), 1);
	assert_eq!(spool_count(dir.path()), 0);
}

#[test]
fn remote_only_message_goes_to_the_spool() {
	let dir = tempfile::tempdir().expect("tempdir");
	let sink = SplitDelivery::new(dir.path(), directory()).expect("sink");
	sink.deliver(message(&["bob@elsewhere.example"]))
		.expect("deliver");
	assert_eq!(inbox_count(dir.path(), "alice"), 0);
	assert_eq!(spool_count(dir.path()), 1);
}

#[test]
fn mixed_message_is_split() {
	let dir = tempfile::tempdir().expect("tempdir");
	let sink = SplitDelivery::new(dir.path(), directory()).expect("sink");
	sink.deliver(message(&["alice@example.org", "bob@elsewhere.example"]))
		.expect("deliver");
	assert_eq!(inbox_count(dir.path(), "alice"), 1);

	let spool = FsSpool::open(dir.path()).expect("spool");
	let ids = spool.list().expect("list");
	assert_eq!(ids.len(), 1);
	let entry = spool.load(ids[0]).expect("load");
	// Only the remote recipient is queued for outbound delivery.
	assert_eq!(
		entry.envelope.recipients,
		vec!["bob@elsewhere.example".to_string()]
	);
}

#[test]
fn unknown_local_user_fails_closed() {
	let dir = tempfile::tempdir().expect("tempdir");
	let sink = SplitDelivery::new(dir.path(), directory()).expect("sink");
	let result = sink.deliver(message(&["stranger@example.org"]));
	assert!(result.is_err());
	assert_eq!(spool_count(dir.path()), 0);
}

#[test]
fn relayed_mail_is_dkim_signed() {
	use std::io::Write;
	let dir = tempfile::tempdir().expect("tempdir");
	// A throwaway DKIM key for the sender domain.
	let (pem, _record) = crate::dkim::generate_key().expect("key");
	let mut key_file = tempfile::NamedTempFile::new().expect("key file");
	key_file.write_all(pem.as_bytes()).expect("write key");
	let signer =
		std::sync::Arc::new(crate::dkim::Signer::load("sel", key_file.path()).expect("load"));

	let sink = SplitDelivery::new(dir.path(), directory())
		.expect("sink")
		.with_signer(signer);
	// DKIM refuses to sign without a From header, so include one.
	let mut msg = message(&["bob@elsewhere.example"]);
	msg.data = b"From: alice@example.org\r\nSubject: hi\r\n\r\nbody\r\n".to_vec();
	sink.deliver(msg).expect("deliver");

	let spool = FsSpool::open(dir.path()).expect("spool");
	let ids = spool.list().expect("list");
	assert_eq!(ids.len(), 1);
	let entry = spool.load(ids[0]).expect("load");
	let data = String::from_utf8_lossy(&entry.data);
	// The relayed copy carries a DKIM-Signature for the sender domain.
	assert!(data.starts_with("DKIM-Signature:"), "{data}");
	assert!(data.contains("d=example.org"), "{data}");
}

#[test]
fn header_of_extracts_named_header() {
	assert_eq!(
		header_of(
			b"From: a@b\r\nSubject: Hello there\r\n\r\nbody\r\n",
			"subject"
		)
		.as_deref(),
		Some("Hello there")
	);
	assert!(header_of(b"From: a@b\r\n\r\nno subject\r\n", "subject").is_none());
}

#[tokio::test]
async fn local_delivery_fires_message_received_webhook() {
	use std::sync::{Arc, Mutex};

	let captured: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
	let state = captured.clone();
	async fn handler(
		axum::extract::State(state): axum::extract::State<Arc<Mutex<Option<String>>>>,
		body: String,
	) -> &'static str {
		*state.lock().expect("lock") = Some(body);
		"ok"
	}
	let app = axum::Router::new()
		.route("/hook", axum::routing::post(handler))
		.with_state(state);
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
		.await
		.expect("bind");
	let addr = listener.local_addr().expect("addr");
	tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });

	let dir = tempfile::tempdir().expect("tempdir");
	let webhook = crate::webhook::Webhook::new(&format!("http://{addr}/hook"), None).expect("wh");
	let sink = SplitDelivery::new(dir.path(), directory())
		.expect("sink")
		.with_webhook(Arc::new(webhook));

	let mut msg = message(&["alice@example.org"]);
	msg.data =
		b"From: bob@example.net\r\nSubject: ping\r\nMessage-ID: <abc@example.net>\r\n\r\nhi\r\n"
			.to_vec();
	sink.deliver(msg).expect("deliver");

	// The notify is fire-and-forget; wait briefly for the spawned task.
	let mut body = None;
	for _ in 0..50 {
		if let Some(b) = captured.lock().expect("lock").clone() {
			body = Some(b);
			break;
		}
		tokio::time::sleep(std::time::Duration::from_millis(10)).await;
	}
	let body = body.expect("webhook delivered");
	assert!(body.contains("message_received"), "{body}");
	assert!(body.contains("alice@example.org"), "{body}");
	assert!(body.contains("\"subject\":\"ping\""), "{body}");
	assert!(
		body.contains("\"message_id\":\"<abc@example.net>\""),
		"{body}"
	);
}
