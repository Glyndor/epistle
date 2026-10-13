//! The delivery-failure webhook says what kind of failure it was and which
//! server gave which reply.

use super::*;
use crate::queue::test_remote::{FakeRemote, Script};
use crate::smtp::session::AcceptedMessage;
use crate::smtp::sink::{MemorySink, MessageSink};
use std::sync::Mutex;

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

#[tokio::test]
async fn the_failure_event_carries_the_class_the_remote_and_its_reply() {
	let (url, captured) = receiver().await;
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = FsSpool::open(dir.path()).expect("spool");
	spool
		.store(&AcceptedMessage {
			reverse_path: "alice@sender.example".into(),
			recipients: vec!["carol@remote.example".into()],
			data: b"Subject: hi\r\n\r\nbody\r\n".to_vec(),
			require_tls: false,
			mailbox: None,
			tlsrpt_verified: false,
			no_dsn: Vec::new(),
		})
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

	let mut body = None;
	for _ in 0..100 {
		if let Some(first) = captured.lock().expect("lock").first().cloned() {
			body = Some(first);
			break;
		}
		tokio::time::sleep(Duration::from_millis(10)).await;
	}
	let event: serde_json::Value =
		serde_json::from_str(&body.expect("webhook delivered")).expect("json");
	assert_eq!(event["event"], "delivery_failed");
	assert_eq!(event["recipient"], "carol@remote.example");
	assert_eq!(event["class"], "policy_rejected");
	assert_eq!(event["remote"], "mx.remote.example");
	assert_eq!(event["reason"], "550 5.7.1 rejected by policy");
}
