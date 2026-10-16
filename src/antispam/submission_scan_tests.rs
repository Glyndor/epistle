use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Duration;

use tracing_subscriber::layer::SubscriberExt;

use super::*;
use crate::antispam::clamd::fake::{FakeClamd, SIGNATURE, eicar};
use crate::smtp::sink::MemorySink;

fn message(body: &str) -> AcceptedMessage {
	AcceptedMessage {
		reverse_path: "alice@example.org".into(),
		recipients: vec!["bob@elsewhere.example".into()],
		data: format!("From: alice@example.org\r\nSubject: s\r\n\r\n{body}\r\n").into_bytes(),
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: false,
		no_dsn: Vec::new(),
	}
}

/// A scanning sink over a fresh memory sink, with clamd at `socket`.
fn sink(
	enabled: bool,
	socket: &std::path::Path,
	webhook: Option<Arc<Webhook>>,
) -> (Arc<dyn MessageSink>, Arc<MemorySink>, Arc<Metrics>) {
	let inner = Arc::new(MemorySink::new());
	let metrics = Arc::new(Metrics::new());
	let clamd = Arc::new(ClamdHook::new(socket.to_path_buf()).with_metrics(metrics.clone()));
	let sink = ScanningSink::wrap(
		enabled,
		inner.clone(),
		Some(clamd),
		Some(metrics.clone()),
		webhook,
	)
	.expect("scanner");
	(sink, inner, metrics)
}

fn submit(sink: &Arc<dyn MessageSink>, body: &str) -> Result<(), SinkError> {
	sink.submit(
		message(body),
		uuid::Uuid::now_v7(),
		"alice",
		&BTreeMap::new(),
	)
}

#[tokio::test]
async fn a_submission_carrying_a_virus_is_refused_with_its_signature() {
	let clamd = FakeClamd::start();
	let (sink, inner, metrics) = sink(true, &clamd.socket, None);
	match submit(&sink, &eicar()) {
		Err(SinkError::VirusDetected(signature)) => assert_eq!(signature, SIGNATURE),
		Err(SinkError::Unavailable(_)) => {
			panic!("expected a virus refusal, got a storage-unavailable refusal")
		}
		Err(SinkError::AttachmentRefused(_)) => {
			panic!("expected a virus refusal, got an attachment refusal")
		}
		Err(SinkError::ScanUnavailable) => {
			panic!("expected a virus refusal, got a busy scanner")
		}
		Err(SinkError::ScanTooLarge) => {
			panic!("expected a virus refusal, got a message too large to scan")
		}
		Ok(()) => panic!("expected a virus refusal, the submission was accepted"),
	}
	assert!(
		inner.messages().is_empty(),
		"nothing reached the routing sink"
	);
	assert_eq!(metrics.snapshot().get("outbound_virus"), Some(&1));
}

#[tokio::test]
async fn a_clean_submission_is_scanned_and_handed_on() {
	let clamd = FakeClamd::start();
	let (sink, inner, metrics) = sink(true, &clamd.socket, None);
	submit(&sink, "nothing to see").expect("accepted");
	assert_eq!(clamd.scans(), 1, "the clean message was scanned");
	assert_eq!(inner.messages().len(), 1);
	assert_eq!(metrics.snapshot().get("outbound_virus"), Some(&0));
}

#[tokio::test]
async fn mail_from_elsewhere_is_not_scanned_here() {
	let clamd = FakeClamd::start();
	let (sink, inner, _) = sink(true, &clamd.socket, None);
	sink.deliver(message(&eicar()))
		.expect("inbound passes through");
	assert_eq!(clamd.scans(), 0);
	assert_eq!(inner.messages().len(), 1);
}

#[tokio::test]
async fn switched_off_the_sink_is_the_routing_sink_itself() {
	let clamd = FakeClamd::start();
	let (sink, inner, _) = sink(false, &clamd.socket, None);
	submit(&sink, &eicar()).expect("not scanned when off");
	assert_eq!(clamd.scans(), 0);
	assert_eq!(inner.messages().len(), 1);
	let inner: Arc<dyn MessageSink> = Arc::new(MemorySink::new());
	let unwrapped = ScanningSink::wrap(true, inner.clone(), None, None, None).expect("sink");
	assert!(
		Arc::ptr_eq(&inner, &unwrapped),
		"without clamd nothing is wrapped"
	);
}

#[tokio::test]
async fn an_unreachable_clamd_accepts_and_leaves_a_record_for_status() {
	let dir = tempfile::tempdir().expect("tempdir");
	let inner = Arc::new(MemorySink::new());
	let clamd =
		Arc::new(ClamdHook::new(dir.path().join("missing.sock")).with_health_file(dir.path()));
	let sink = ScanningSink::wrap(true, inner.clone(), Some(clamd), None, None).expect("sink");
	submit(&sink, &eicar()).expect("fails open");
	assert_eq!(inner.messages().len(), 1);
	let health = crate::antispam::clamd::health::read(dir.path()).expect("recorded");
	assert_eq!(health.failures, 1);
	assert!(health.failing_since.is_some());
}

#[derive(Clone, Default)]
struct Warnings(Arc<Mutex<Vec<String>>>);

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Warnings {
	fn on_event(
		&self,
		event: &tracing::Event<'_>,
		_ctx: tracing_subscriber::layer::Context<'_, S>,
	) {
		if *event.metadata().level() == tracing::Level::WARN {
			let mut fields = String::new();
			event.record(
				&mut |field: &tracing::field::Field, value: &dyn std::fmt::Debug| {
					use std::fmt::Write;
					let _ = write!(&mut fields, "{field}={value:?};");
				},
			);
			self.0.lock().expect("warnings").push(fields);
		}
	}
}

#[test]
fn a_detection_logs_the_account_pseudonym_and_the_signature() {
	let clamd = FakeClamd::start();
	let (sink, _, _) = sink(true, &clamd.socket, None);
	crate::cli::tracing_capture::keep_callsites_live();
	let warnings = Warnings::default();
	let subscriber = tracing_subscriber::registry().with(warnings.clone());
	tracing::subscriber::with_default(subscriber, || {
		let _ = submit(&sink, &eicar());
	});
	let lines = warnings.0.lock().expect("warnings").join("\n");
	assert!(
		lines.contains(&crate::log_id::account("alice")),
		"pseudonym: {lines}"
	);
	assert!(lines.contains(SIGNATURE), "signature: {lines}");
	assert!(
		!lines.contains("alice"),
		"the account name stays out: {lines}"
	);
}

#[tokio::test]
async fn a_detection_fires_the_outbound_virus_webhook() {
	let (sender, mut received) = tokio::sync::mpsc::unbounded_channel::<String>();
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
		.await
		.expect("bind");
	let address = listener.local_addr().expect("addr");
	let app = axum::Router::new().route(
		"/hook",
		axum::routing::post(move |body: String| {
			let sender = sender.clone();
			async move {
				let _ = sender.send(body);
				"ok"
			}
		}),
	);
	tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });
	let webhook = Arc::new(Webhook::new(&format!("http://{address}/hook"), None).expect("webhook"));
	let clamd = FakeClamd::start();
	let (sink, _, _) = sink(true, &clamd.socket, Some(webhook));
	assert!(submit(&sink, &eicar()).is_err());
	let body = tokio::time::timeout(Duration::from_secs(5), received.recv())
		.await
		.expect("the webhook arrived")
		.expect("a body");
	let event: serde_json::Value = serde_json::from_str(&body).expect("json");
	assert_eq!(
		event,
		serde_json::json!({"event": "outbound_virus", "account": "alice", "signature": SIGNATURE})
	);
}

#[test]
fn a_long_signature_is_cut_for_the_reply() {
	let long = "x".repeat(500);
	assert_eq!(bounded(&long).chars().count(), MAX_SIGNATURE_CHARS);
	assert_eq!(bounded(SIGNATURE), SIGNATURE);
}

/// A scanning sink over a memory sink, kept concrete so a test can read
/// which threads scanned.
fn concrete(socket: &std::path::Path) -> ScanningSink {
	ScanningSink {
		inner: Arc::new(MemorySink::new()),
		scanner: Some(
			worker::Scanner::start(Arc::new(ClamdHook::new(socket.to_path_buf())))
				.expect("scanner"),
		),
		defer_unscanned: false,
		attachments: None,
		gate: gate::Gate::new(4, 1),
		metrics: None,
		webhook: None,
		workers: Default::default(),
	}
}

#[tokio::test]
async fn sequential_scans_share_one_worker() {
	let clamd = FakeClamd::start();
	let sink = concrete(&clamd.socket);
	for _ in 0..50 {
		sink.submit(
			message("hello"),
			uuid::Uuid::now_v7(),
			"alice",
			&BTreeMap::new(),
		)
		.expect("clean");
	}
	assert_eq!(clamd.scans(), 50);
	let workers = sink.workers.lock().expect("workers");
	assert_eq!(
		workers.len(),
		1,
		"one long-lived scanner, not one per message"
	);
	assert!(
		!workers.contains(&std::thread::current().id()),
		"the scan does not run on the caller's runtime thread"
	);
}

/// How long 200 small submissions take against the fake clamd. Run with
/// `cargo test --lib two_hundred -- --ignored --nocapture`.
#[tokio::test]
#[ignore = "a measurement, not a check"]
async fn two_hundred_small_scans_timing() {
	let clamd = FakeClamd::start();
	let sink = concrete(&clamd.socket);
	let started = std::time::Instant::now();
	for _ in 0..200 {
		sink.submit(
			message("hello"),
			uuid::Uuid::now_v7(),
			"alice",
			&BTreeMap::new(),
		)
		.expect("clean");
	}
	println!("200 small submissions scanned in {:?}", started.elapsed());
}

#[tokio::test]
async fn a_silent_clamd_is_cut_off_at_its_deadline() {
	let dir = tempfile::tempdir().expect("tempdir");
	let socket = dir.path().join("clamd.sock");
	let listener = std::os::unix::net::UnixListener::bind(&socket).expect("bind");
	// Accept and never answer.
	std::thread::spawn(move || {
		let held: Vec<_> = listener.incoming().take(1).collect();
		std::thread::sleep(Duration::from_secs(10));
		drop(held);
	});
	let clamd = Arc::new(ClamdHook::new(socket).with_timeout(Duration::from_millis(200)));
	let inner = Arc::new(MemorySink::new());
	let sink = ScanningSink::wrap(true, inner.clone(), Some(clamd), None, None).expect("sink");
	let started = std::time::Instant::now();
	submit(&sink, &eicar()).expect("fails open");
	assert!(
		started.elapsed() < Duration::from_secs(2),
		"{:?}",
		started.elapsed()
	);
	assert_eq!(inner.messages().len(), 1);
}
