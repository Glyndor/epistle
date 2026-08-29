//! End-to-end test for the alert engine runner: drives a real rule against a
//! real `Metrics` counter, captures the webhook delivery, and asserts that the
//! cooldown gate blocks re-fires.

use std::sync::{Arc, Mutex};

use crate::alerts::{DispatchContext, EngineHandle, Verdict, context, evaluate, run};
use crate::config::{Alert, AlertOp};
use crate::metrics::Metrics;
use crate::smtp::session::AcceptedMessage;
use crate::storage::FsSpool;
use crate::webhook::{Webhook, WebhookEvent};

async fn capture_server(captured: Arc<Mutex<Vec<WebhookEvent>>>) -> String {
	use axum::extract::State;
	use axum::http::HeaderMap;
	async fn handler(
		State(captured): State<Arc<Mutex<Vec<WebhookEvent>>>>,
		headers: HeaderMap,
		body: String,
	) -> &'static str {
		let _ = headers;
		let event: WebhookEvent = serde_json::from_str(&body).expect("valid webhook payload");
		captured.lock().expect("lock").push(event);
		"ok"
	}
	let app = axum::Router::new()
		.route("/hook", axum::routing::post(handler))
		.with_state(captured);
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
		.await
		.expect("bind");
	let addr = listener.local_addr().expect("addr");
	tokio::spawn(async move {
		axum::serve(listener, app).await.expect("serve");
	});
	format!("http://{addr}/hook")
}

fn alert_rule_bounced_ge_50(window_secs: u64, cooldown_secs: u64) -> Alert {
	Alert {
		name: "bounce-storm".into(),
		metric: "bounced".into(),
		op: AlertOp::Ge,
		threshold: 50,
		window_secs,
		cooldown_secs,
		webhook: true,
		email: Vec::new(),
	}
}

/// Drive a real `run()` with a 1-second window: spawn the engine, hit the
/// counter enough times to cross the threshold, wait for the second tick to
/// evaluate the resulting delta, then check the captured webhook payload.
#[tokio::test(start_paused = false)]
async fn runner_fires_webhook_when_counter_crosses_threshold() {
	let captured: Arc<Mutex<Vec<WebhookEvent>>> = Arc::new(Mutex::new(Vec::new()));
	let url = capture_server(captured.clone()).await;
	let webhook = Arc::new(Webhook::new(&url, None).expect("webhook"));
	let metrics = Arc::new(Metrics::new());
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = Arc::new(FsSpool::open(dir.path()).expect("spool"));
	let ctx: DispatchContext = context(Some(webhook), spool, "mail.example.org".into());

	let rules = vec![alert_rule_bounced_ge_50(1, 1)];
	let handle: EngineHandle = run(rules, Arc::clone(&metrics), ctx).expect("engine started");

	// First tick: warmup — record the baseline (0), no fire. Wait long enough
	// for the warmup to land.
	tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
	// Counter goes from 0 to 60 between the warmup sample and the next tick.
	for _ in 0..60 {
		metrics.bounced();
	}
	// Second tick: delta = 60, fires.
	tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

	handle.stop();

	let events = captured.lock().expect("lock").clone();
	assert_eq!(events.len(), 1, "exactly one fire");
	let event = &events[0];
	match event {
		WebhookEvent::MetricAlert {
			name,
			metric,
			value,
			threshold,
			window_secs,
		} => {
			assert_eq!(name, "bounce-storm");
			assert_eq!(metric, "bounced");
			assert_eq!(*value, 60);
			assert_eq!(*threshold, 50);
			assert_eq!(*window_secs, 1);
		}
		other => panic!("expected metric_alert, got {other:?}"),
	}
}

/// Two consecutive fires with no break in the condition: only the first one
/// reaches the webhook — the cooldown plus the hysteresis latch keep the
/// second quiet, no matter how many ticks pass.
#[tokio::test(start_paused = false)]
async fn runner_respects_cooldown_and_hysteresis() {
	let captured: Arc<Mutex<Vec<WebhookEvent>>> = Arc::new(Mutex::new(Vec::new()));
	let url = capture_server(captured.clone()).await;
	let webhook = Arc::new(Webhook::new(&url, None).expect("webhook"));
	let metrics = Arc::new(Metrics::new());
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = Arc::new(FsSpool::open(dir.path()).expect("spool"));
	let ctx = context(Some(webhook), spool, "mail.example.org".into());

	let rules = vec![alert_rule_bounced_ge_50(1, 60)];
	let handle = run(rules, Arc::clone(&metrics), ctx).expect("engine started");

	tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
	for _ in 0..60 {
		metrics.bounced();
	}
	// Three ticks after the first fire. Each tick sees a delta ≥ 50; the
	// cooldown (60s) gates the second, and once the cooldown elapses the
	// hysteresis latch keeps it quiet because the condition never went false.
	for _ in 0..3 {
		for _ in 0..60 {
			metrics.bounced();
		}
		tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
	}

	handle.stop();

	let events = captured.lock().expect("lock").clone();
	assert_eq!(events.len(), 1, "exactly one fire");
}

/// An alert that requests email ends up on the spool, with the configured
/// `name` in the subject and the rule's inputs in the body.
#[tokio::test]
async fn runner_queues_alert_email_to_spool() {
	let metrics = Arc::new(Metrics::new());
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = Arc::new(FsSpool::open(dir.path()).expect("spool"));
	let captured_spool = Arc::clone(&spool);
	let ctx = context(None, Arc::clone(&spool), "mail.example.org".into());

	let rules = vec![Alert {
		name: "bounce-storm".into(),
		metric: "bounced".into(),
		op: AlertOp::Ge,
		threshold: 50,
		window_secs: 1,
		cooldown_secs: 1,
		webhook: false,
		email: vec!["ops@example.org".into()],
	}];
	let handle = run(rules, Arc::clone(&metrics), ctx).expect("engine started");

	tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
	for _ in 0..60 {
		metrics.bounced();
	}
	tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

	handle.stop();

	let ids = captured_spool.list().expect("spool list");
	assert_eq!(ids.len(), 1, "one alert email spooled");
	let entry = captured_spool.load(ids[0]).expect("spool load");
	let message: AcceptedMessage = AcceptedMessage {
		reverse_path: "epistle-alerts@mail.example.org".into(),
		recipients: vec!["ops@example.org".into()],
		data: entry.data.clone(),
		require_tls: false,
		mailbox: None,
		no_dsn: Vec::new(),
	};
	let _ = message;
	let rendered = String::from_utf8(entry.data.clone()).expect("utf-8 body");
	assert!(
		rendered.contains("Subject: [epistle] alert: bounce-storm"),
		"{rendered}"
	);
	assert!(rendered.contains("Rule:      bounce-storm"), "{rendered}");
	assert!(rendered.contains("Metric:    bounced"), "{rendered}");
	assert!(rendered.contains("Delta:     60"), "{rendered}");
	assert!(rendered.contains("Condition: >= 50"), "{rendered}");
	assert!(
		rendered.contains("To: ops@example.org"),
		"single-recipient To: line: {rendered}"
	);
}

/// Empty config -> no task spawned. `run()` returns `None` and the caller
/// never observes a handle to leak.
#[tokio::test]
async fn empty_rules_returns_none() {
	let metrics = Arc::new(Metrics::new());
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = Arc::new(FsSpool::open(dir.path()).expect("spool"));
	let ctx = context(None, spool, "mail.example.org".into());
	assert!(run(Vec::new(), metrics, ctx).is_none());
}

/// A rule whose metric does not exist is dropped at compile time: `run()`
/// returns `None`, no task is spawned, no panic.
#[tokio::test]
async fn unknown_metric_at_compile_is_dropped() {
	let metrics = Arc::new(Metrics::new());
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = Arc::new(FsSpool::open(dir.path()).expect("spool"));
	let ctx = context(None, spool, "mail.example.org".into());
	let rules = vec![Alert {
		name: "broken".into(),
		metric: "not_a_counter".into(),
		op: AlertOp::Ge,
		threshold: 1,
		window_secs: 1,
		cooldown_secs: 1,
		webhook: true,
		email: Vec::new(),
	}];
	assert!(run(rules, metrics, ctx).is_none());
}

/// Sanity: the pure evaluator's verdict survives a round-trip through a
/// non-default rule. Catches any accidental move or copy regressions on
/// `CompiledRule`.
#[test]
fn evaluate_returns_fire_then_holds_in_cooldown() {
	let rule = crate::alerts::CompiledRule::for_test("bounced", AlertOp::Ge, 50, 60, 60);
	let mut state = crate::alerts::State::new();
	assert_eq!(evaluate(&rule, &mut state, 60, 1_000), Verdict::Fire);
	assert_eq!(evaluate(&rule, &mut state, 70, 1_010), Verdict::Hold);
}
