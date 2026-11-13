//! Tests for delivery routing (SplitDelivery).

use super::*;
use std::fs;

pub(super) fn directory() -> DirectoryHandle {
	DirectoryHandle::new(crate::smtp::directory::Directory::new(
		["example.org".to_string()],
		[("alice@example.org".to_string(), "alice".to_string())],
	))
}

pub(super) fn message(recipients: &[&str]) -> AcceptedMessage {
	AcceptedMessage {
		reverse_path: "alice@example.org".into(),
		recipients: recipients.iter().map(|r| r.to_string()).collect(),
		data: b"Subject: hi\r\n\r\nbody\r\n".to_vec(),
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: false,
		no_dsn: Vec::new(),
	}
}

pub(super) fn inbox_count(root: &std::path::Path, account: &str) -> usize {
	fs::read_dir(root.join("accounts").join(account).join("new"))
		.map(|entries| entries.count())
		.unwrap_or(0)
}

pub(super) fn spool_count(root: &std::path::Path) -> usize {
	FsSpool::open(root)
		.expect("open spool")
		.list()
		.expect("list")
		.len()
}

pub(super) fn folder_count(root: &std::path::Path, account: &str, mailbox: &str) -> usize {
	fs::read_dir(
		root.join("accounts")
			.join(account)
			.join("folders")
			.join(mailbox)
			.join("new"),
	)
	.map(|entries| {
		entries
			.flatten()
			.filter(|entry| entry.file_name().to_string_lossy().ends_with(".eml"))
			.count()
	})
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
		.with_signer(crate::dkim::PerDomainSigner::new(
			crate::dkim::ReloadableSigner::new(signer),
			Vec::new(),
		));
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
	let webhook =
		crate::webhook::Webhook::new_allowing_private(&format!("http://{addr}/hook"), None)
			.expect("wh");
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
