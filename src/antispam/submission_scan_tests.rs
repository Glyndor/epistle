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
	);
	(sink, inner, metrics)
}

fn submit(sink: &Arc<dyn MessageSink>, body: &str) -> Result<(), SinkError> {
	sink.submit(message(body), uuid::Uuid::now_v7(), "alice")
}

#[tokio::test]
async fn a_submission_carrying_a_virus_is_refused_with_its_signature() {
	let clamd = FakeClamd::start();
	let (sink, inner, metrics) = sink(true, &clamd.socket, None);
	match submit(&sink, &eicar()) {
		Err(SinkError::VirusDetected(signature)) => assert_eq!(signature, SIGNATURE),
		other => panic!("expected a virus refusal, got {other:?}"),
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
	let unwrapped = ScanningSink::wrap(true, inner.clone(), None, None, None);
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
	let sink = ScanningSink::wrap(true, inner.clone(), Some(clamd), None, None);
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
	let warnings = Warnings::default();
	let subscriber = tracing_subscriber::registry().with(warnings.clone());
	tracing::subscriber::with_default(subscriber, || {
		// Other tests reach the same warning at the same time on threads
		// without a subscriber; without a rebuild the callsite can stay
		// cached as uninteresting and this subscriber sees nothing.
		tracing::callsite::rebuild_interest_cache();
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
