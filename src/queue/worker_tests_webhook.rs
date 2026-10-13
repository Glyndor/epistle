//! The delivery-failure webhook says what kind of failure it was and which
//! server gave which reply. The `Delivered`, `Delayed` and `Suppressed`
//! events follow the same plumbing; their firing and their dedup rules are
//! the reason this file exists.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Duration;

use super::*;
use crate::queue::test_remote::{FakeRemote, Script};
use crate::smtp::session::AcceptedMessage;
use crate::smtp::sink::{MemorySink, MessageSink};

/// Start a webhook receiver; returns its URL and the bodies it got.
async fn receiver() -> (String, Arc<Mutex<Vec<String>>>) {
	let captured: Arc<Mutex<Vec<String>>> = Arc::default();
	async fn handler(
		axum::extract::State(state): axum::extract::State<Arc<Mutex<Vec<String>>>>,
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

/// Wait until `predicate` returns true or give up after ~1 s of polling.
async fn wait_for<F>(predicate: F)
where
	F: Fn() -> bool,
{
	for _ in 0..100 {
		if predicate() {
			return;
		}
		tokio::time::sleep(Duration::from_millis(10)).await;
	}
}

#[tokio::test]
async fn the_failure_event_carries_the_class_the_remote_and_its_reply() {
	let (url, captured) = receiver().await;
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = FsSpool::open(dir.path()).expect("spool");
	spool
		.store(
			&AcceptedMessage {
				reverse_path: "alice@sender.example".into(),
				recipients: vec!["carol@remote.example".into()],
				data: b"Subject: hi\r\n\r\nbody\r\n".to_vec(),
				require_tls: false,
				mailbox: None,
				tlsrpt_verified: false,
				no_dsn: Vec::new(),
			},
			None,
			&BTreeMap::new(),
		)
		.expect("store");
	let remote = FakeRemote::default();
	remote.script(
		"remote.example",
		Script::rcpt("carol@remote.example", "550 5.7.1 rejected by policy"),
	);
	let webhook = crate::webhook::Webhook::new(&url, None).expect("webhook");
	let worker = Worker::new(spool, Arc::new(remote), "mail.sender.example")
		.with_bounce_sink(Arc::new(MemorySink::new()) as Arc<dyn MessageSink>)
		.with_webhook(Arc::new(webhook));
	worker.pass().await.expect("pass");

	wait_for(|| !captured.lock().expect("lock").is_empty()).await;
	let body = captured.lock().expect("lock")[0].clone();
	let event: serde_json::Value = serde_json::from_str(&body).expect("json");
	assert_eq!(event["event"], "delivery_failed");
	assert_eq!(event["recipient"], "carol@remote.example");
	assert_eq!(event["class"], "policy_rejected");
	assert_eq!(event["remote"], "mx.remote.example");
	assert_eq!(event["reason"], "550 5.7.1 rejected by policy");
}

#[tokio::test]
async fn the_delivered_event_carries_the_message_id_the_remote_and_the_extra() {
	let (url, captured) = receiver().await;
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = FsSpool::open(dir.path()).expect("spool");
	let mut extra = BTreeMap::new();
	extra.insert("trace_id".into(), "abc-123".into());
	let id = spool
		.store(
			&AcceptedMessage {
				reverse_path: "alice@sender.example".into(),
				recipients: vec!["bob@remote.example".into()],
				data: b"Message-ID: <m1@elsewhere.example>\r\nSubject: hi\r\n\r\nbody\r\n".to_vec(),
				require_tls: false,
				mailbox: None,
				tlsrpt_verified: false,
				no_dsn: Vec::new(),
			},
			Some("alice"),
			&extra,
		)
		.expect("store");
	let remote = FakeRemote::default();
	remote.script(
		"remote.example",
		Script::rcpt("bob@remote.example", "250 OK"),
	);
	let webhook = crate::webhook::Webhook::new(&url, None).expect("webhook");
	let worker = Worker::new(spool, Arc::new(remote), "mail.sender.example")
		.with_bounce_sink(Arc::new(MemorySink::new()) as Arc<dyn MessageSink>)
		.with_webhook(Arc::new(webhook));
	worker.pass().await.expect("pass");

	wait_for(|| !captured.lock().expect("lock").is_empty()).await;
	let bodies = captured.lock().expect("lock").clone();
	let body = bodies
		.iter()
		.find(|body| body.contains("\"event\":\"delivered\""))
		.expect("delivered body");
	let event: serde_json::Value = serde_json::from_str(body).expect("json");
	assert_eq!(event["recipient"], "bob@remote.example");
	assert_eq!(event["message_id"], "<m1@elsewhere.example>");
	assert_eq!(event["remote"], "mx.remote.example");
	assert_eq!(event["spool_id"], id.to_string());
	assert_eq!(event["extra"]["trace_id"], "abc-123");
}

#[tokio::test]
async fn delayed_fires_once_across_several_retries() {
	// The first deferral fires `delayed`; the next attempt of the same
	// recipient must not, even when the worker keeps trying and the
	// remote keeps refusing. Otherwise a slow remote burns the
	// webhook.
	let (url, captured) = receiver().await;
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = FsSpool::open(dir.path()).expect("spool");
	spool
		.store(
			&AcceptedMessage {
				reverse_path: "alice@sender.example".into(),
				recipients: vec!["bob@remote.example".into()],
				data: b"Subject: hi\r\n\r\nbody\r\n".to_vec(),
				require_tls: false,
				mailbox: None,
				tlsrpt_verified: false,
				no_dsn: Vec::new(),
			},
			None,
			&BTreeMap::new(),
		)
		.expect("store");
	let remote = FakeRemote::default();
	remote.script(
		"remote.example",
		Script::rcpt("bob@remote.example", "451 4.3.0 later"),
	);
	let webhook = crate::webhook::Webhook::new(&url, None).expect("webhook");
	let worker = Worker::new(spool, Arc::new(remote), "mail.sender.example")
		.with_bounce_sink(Arc::new(MemorySink::new()) as Arc<dyn MessageSink>)
		.with_webhook(Arc::new(webhook))
		// base=0, cap=0 -> the next attempt is `now`, so every pass
		// re-tries immediately.
		.with_retry_schedule(crate::queue::RetrySchedule {
			base: 0,
			cap: 0,
			delay_warning: 0,
		});
	let start = worker
		.spool
		.list()
		.expect("list")
		.into_iter()
		.next()
		.expect("entry")
		.get_timestamp()
		.expect("v7")
		.to_unix()
		.0;
	for offset in 0..5 {
		worker.set_now(start + offset + 1);
		worker.pass().await.expect("pass");
	}

	wait_for(|| !captured.lock().expect("lock").is_empty()).await;
	// One last quiet beat so any (wrong) extra `delayed` body would land.
	tokio::time::sleep(Duration::from_millis(50)).await;
	let bodies = captured.lock().expect("lock").clone();
	assert_eq!(
		bodies.iter().filter(|body| body.contains("\"event\":\"delayed\"")).count(),
		1,
		"exactly one delayed event across all retries: {bodies:?}"
	);
	let body = bodies
		.iter()
		.find(|body| body.contains("\"event\":\"delayed\""))
		.expect("a delayed body");
	let event: serde_json::Value = serde_json::from_str(body).expect("json");
	assert_eq!(event["attempt"], 1);
	assert_eq!(event["reason"], "451 4.3.0 later");
	assert_eq!(event["remote"], "mx.remote.example");
	assert_eq!(event["recipient"], "bob@remote.example");
}

#[tokio::test]
async fn a_suppressed_recipient_emits_a_suppressed_webhook() {
	let (url, captured) = receiver().await;
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = FsSpool::open(dir.path()).expect("spool");
	spool
		.store(
			&AcceptedMessage {
				reverse_path: "alice@sender.example".into(),
				recipients: vec!["bob@suppressed.example".into()],
				data: b"Subject: hi\r\n\r\nbody\r\n".to_vec(),
				require_tls: false,
				mailbox: None,
				tlsrpt_verified: false,
				no_dsn: Vec::new(),
			},
			None,
			&BTreeMap::new(),
		)
		.expect("store");
	let suppression = crate::queue::SuppressionList::open(dir.path()).expect("suppression");
	suppression.suppress("bob@suppressed.example");
	let webhook = crate::webhook::Webhook::new(&url, None).expect("webhook");
	let worker = Worker::new(spool, Arc::new(FakeRemote::default()), "mail.sender.example")
		.with_suppression(suppression)
		.with_bounce_sink(Arc::new(MemorySink::new()) as Arc<dyn MessageSink>)
		.with_webhook(Arc::new(webhook));
	worker.pass().await.expect("pass");

	wait_for(|| !captured.lock().expect("lock").is_empty()).await;
	let body = captured
		.lock()
		.expect("lock")
		.iter()
		.find(|body| body.contains("\"event\":\"suppressed\""))
		.expect("a suppressed body")
		.clone();
	let event: serde_json::Value = serde_json::from_str(&body).expect("json");
	assert_eq!(event["recipient"], "bob@suppressed.example");
	assert!(event.get("extra").is_none(), "empty extra must not serialise");
}
