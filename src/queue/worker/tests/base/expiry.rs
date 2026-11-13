//! Worker tests for expiry, suppression, delay warnings, webhooks and transports.

use super::*;

#[tokio::test]
async fn expired_message_bounces_once() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = spool_with_message(dir.path(), "bob@remote.example");
	let created = created_at(&spool);
	let bounce_sink = Arc::new(MemorySink::new());
	// A 1-hour give-up window for the test (well under the 4h delay warning).
	let worker = Worker::new(spool, Arc::new(DownConnector), "mail.sender.example")
		.with_bounce_sink(bounce_sink.clone() as Arc<dyn MessageSink>)
		.with_max_age(3600);

	// Within the window: deferred, kept, no bounce.
	worker.set_now(created + 60);
	assert_eq!(worker.pass().await.expect("pass"), 0);
	assert_eq!(worker.spool.list().expect("list").len(), 1);
	assert!(bounce_sink.messages().is_empty());

	// Past the window: bounced (Action: failed) and removed.
	worker.set_now(created + 3601);
	assert_eq!(worker.pass().await.expect("pass"), 0);
	assert!(worker.spool.list().expect("list").is_empty());
	let bounces = bounce_sink.messages();
	assert_eq!(bounces.len(), 1);
	let body = String::from_utf8(bounces[0].data.clone()).expect("ascii");
	assert!(body.contains("Action: failed"), "{body}");
}

#[tokio::test]
async fn transient_failure_defers_within_window() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = spool_with_message(dir.path(), "bob@remote.example");
	let created = created_at(&spool);
	// Default 5-day window; retry across the first few hours, all kept.
	let worker = Worker::new(spool, Arc::new(DownConnector), "mail.sender.example");
	for hours in [0u64, 1, 2, 3] {
		worker.set_now(created + hours * 3600 + 1);
		assert_eq!(worker.pass().await.expect("pass"), 0);
		assert_eq!(worker.spool.list().expect("list").len(), 1);
	}
}

#[tokio::test]
async fn permanent_failure_suppresses_then_drops_silently() {
	let dir = tempfile::tempdir().expect("tempdir");
	// carol@ is unknown to the loopback server → permanent 550.
	let spool = spool_with_message(dir.path(), "carol@remote.example");
	let sink = Arc::new(MemorySink::new());
	let connector = Arc::new(LoopbackConnector {
		sink: sink.clone(),
		domain: "remote.example".to_string(),
	});
	let bounce_sink = Arc::new(MemorySink::new());
	let suppression = SuppressionList::open(dir.path()).expect("suppression");
	let worker = Worker::new(spool, connector, "mail.sender.example")
		.with_bounce_sink(bounce_sink.clone() as Arc<dyn MessageSink>)
		.with_suppression(suppression);

	// First send: permanent failure → one bounce, and carol@ is suppressed.
	assert_eq!(worker.pass().await.expect("pass"), 0);
	assert_eq!(bounce_sink.messages().len(), 1);
	let suppression = SuppressionList::open(dir.path()).expect("suppression");
	assert!(suppression.is_suppressed("carol@remote.example"));
	// The bounce is also recorded under the sending account.
	assert!(suppression.is_suppressed_for("alice@sender.example", "carol@remote.example"));

	// A new message to the suppressed recipient is dropped with no new bounce.
	worker
		.spool
		.store(
			&AcceptedMessage {
				reverse_path: "alice@sender.example".into(),
				recipients: vec!["carol@remote.example".to_string()],
				data: b"Subject: again\r\n\r\nx\r\n".to_vec(),
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
	assert_eq!(worker.pass().await.expect("pass"), 0);
	assert!(worker.spool.list().expect("list").is_empty());
	assert_eq!(bounce_sink.messages().len(), 1, "no second bounce");
}

#[tokio::test]
async fn delay_warning_sent_once_after_threshold() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = spool_with_message(dir.path(), "bob@remote.example");
	let created = created_at(&spool);
	let bounce_sink = Arc::new(MemorySink::new());
	let worker = Worker::new(spool, Arc::new(DownConnector), "mail.sender.example")
		.with_bounce_sink(bounce_sink.clone() as Arc<dyn MessageSink>);

	// Past the 4h delay-warning threshold: one "delayed" DSN, message kept.
	worker.set_now(created + 14_401);
	assert_eq!(worker.pass().await.expect("pass"), 0);
	assert_eq!(worker.spool.list().expect("list").len(), 1);
	let messages = bounce_sink.messages();
	assert_eq!(messages.len(), 1);
	let body = String::from_utf8(messages[0].data.clone()).expect("ascii");
	assert!(body.contains("Action: delayed"), "{body}");

	// A later retry does not send a second warning.
	worker.set_now(created + 18_000);
	let _ = worker.pass().await.expect("pass");
	assert_eq!(bounce_sink.messages().len(), 1);
}

#[tokio::test]
async fn permanent_failure_fires_delivery_failed_webhook() {
	use std::sync::Mutex;
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
	let spool = spool_with_message(dir.path(), "carol@remote.example");
	let connector = Arc::new(LoopbackConnector {
		sink: Arc::new(MemorySink::new()),
		domain: "remote.example".to_string(),
	});
	let webhook =
		crate::webhook::Webhook::new_allowing_private(&format!("http://{addr}/hook"), None)
			.expect("wh");
	let worker = Worker::new(spool, connector, "mail.sender.example")
		.with_bounce_sink(Arc::new(MemorySink::new()) as Arc<dyn MessageSink>)
		.with_webhook(Arc::new(webhook));
	worker.pass().await.expect("pass");

	let mut body = None;
	for _ in 0..50 {
		if let Some(b) = captured.lock().expect("lock").clone() {
			body = Some(b);
			break;
		}
		tokio::time::sleep(Duration::from_millis(10)).await;
	}
	let body = body.expect("webhook delivered");
	assert!(body.contains("delivery_failed"), "{body}");
	assert!(body.contains("carol@remote.example"), "{body}");
}

#[tokio::test]
async fn notify_never_suppresses_the_bounce() {
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
				sender_verified: false,
				// The sender asked for no failure DSN.
				no_dsn: vec!["carol@remote.example".into()],
			},
			None,
			&BTreeMap::new(),
		)
		.expect("store");
	let connector = Arc::new(LoopbackConnector {
		sink: Arc::new(MemorySink::new()),
		domain: "remote.example".to_string(),
	});
	let bounce_sink = Arc::new(MemorySink::new());
	let worker = Worker::new(spool, connector, "mail.sender.example")
		.with_bounce_sink(bounce_sink.clone() as Arc<dyn MessageSink>);
	worker.pass().await.expect("pass");

	// carol@ is rejected (550) but NOTIFY=NEVER means no bounce is sent.
	assert!(worker.spool.list().expect("list").is_empty());
	assert!(
		bounce_sink.messages().is_empty(),
		"no bounce for NOTIFY=NEVER"
	);
}

fn fail_rule(domain: &str) -> crate::config::Transport {
	crate::config::Transport {
		account: None,
		domain: Some(domain.to_string()),
		kind: crate::config::TransportKind::Fail,
		host: None,
		port: None,
		starttls: false,
		username: None,
		password: None,
		socks_proxy: None,
		enabled: true,
	}
}

#[tokio::test]
async fn fail_transport_drops_without_connecting() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = spool_with_message(dir.path(), "bob@remote.example");
	let sink = Arc::new(MemorySink::new());
	let connector = Arc::new(LoopbackConnector {
		sink: sink.clone(),
		domain: "remote.example".to_string(),
	});
	let bounce_sink = Arc::new(MemorySink::new());

	let worker = Worker::new(spool, connector, "mail.sender.example")
		.with_bounce_sink(bounce_sink.clone() as Arc<dyn MessageSink>)
		.with_transports(vec![fail_rule("remote.example")]);
	let delivered = worker.pass().await.expect("pass");

	// The fail transport refuses: nothing delivered to the remote, message
	// dropped and bounced to the sender.
	assert_eq!(delivered, 0);
	assert!(sink.messages().is_empty());
	assert!(worker.spool.list().expect("list").is_empty());
	assert_eq!(bounce_sink.messages().len(), 1);
}

#[tokio::test]
async fn direct_kind_still_delivers_via_mx() {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = spool_with_message(dir.path(), "bob@remote.example");
	let sink = Arc::new(MemorySink::new());
	let connector = Arc::new(LoopbackConnector {
		sink: sink.clone(),
		domain: "remote.example".to_string(),
	});
	let mut direct = fail_rule("remote.example");
	direct.kind = crate::config::TransportKind::Direct;

	let worker = Worker::new(spool, connector, "mail.sender.example").with_transports(vec![direct]);
	assert_eq!(worker.pass().await.expect("pass"), 1);
	assert_eq!(sink.messages().len(), 1);
}
