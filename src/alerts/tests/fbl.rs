//! The complaint counter feeds the alert engine: a burst of complaints read
//! from feedback-loop reports crosses the rule the operator wrote.

use std::sync::{Arc, Mutex};

use super::integration::capture_server;
use crate::alerts::{CompiledRule, context, run};
use crate::config::{Alert, AlertOp};
use crate::metrics::Metrics;
use crate::reports::fbl::test_support::{directory, fbl, valid_report, verified};
use crate::reports::fbl::{Outcome, process};
use crate::smtp::session::AcceptedMessage;
use crate::storage::FsSpool;
use crate::webhook::{Webhook, WebhookEvent};

fn rule(threshold: u64) -> Alert {
	Alert {
		name: "complaints".into(),
		metric: "fbl_complaints".into(),
		op: AlertOp::Ge,
		threshold,
		window_secs: 1,
		cooldown_secs: 60,
		enabled: true,
		webhook: true,
		email: Vec::new(),
	}
}

fn complaint(recipient: &str) -> AcceptedMessage {
	verified(valid_report(recipient))
}

#[test]
fn the_complaint_counter_is_a_metric_the_alert_engine_accepts() {
	assert!(crate::metrics::metric_names().contains(&"fbl_complaints"));
	CompiledRule::from_alert(&rule(5)).expect("a rule on the complaint counter compiles");
}

#[tokio::test]
async fn a_burst_of_complaints_fires_the_alert() {
	let captured: Arc<Mutex<Vec<WebhookEvent>>> = Arc::new(Mutex::new(Vec::new()));
	let url = capture_server(captured.clone()).await;
	let webhook = Arc::new(Webhook::new_allowing_private(&url, None).expect("webhook"));
	let metrics = Arc::new(Metrics::new());
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = Arc::new(FsSpool::open(dir.path()).expect("spool"));
	let ctx = context(Some(webhook), spool, "mail.example.org".into(), true, true);
	let handle = run(vec![rule(3)], Arc::clone(&metrics), ctx).expect("engine started");
	tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

	let fbl = fbl("");
	let directory = directory();
	for n in 0..3 {
		let message = complaint(&format!("victim{n}@example.com"));
		let outcome = process(&fbl, dir.path(), &directory, &message, Some(&metrics));
		assert!(matches!(outcome, Outcome::Counted { .. }));
	}
	tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
	handle.stop();

	let events = captured.lock().expect("lock").clone();
	assert_eq!(events.len(), 1, "one fire");
	match &events[0] {
		WebhookEvent::MetricAlert { metric, value, .. } => {
			assert_eq!(metric, "fbl_complaints");
			assert_eq!(*value, 3);
		}
		other => panic!("expected metric_alert, got {other:?}"),
	}
}

#[tokio::test]
async fn complaints_below_the_threshold_do_not_fire() {
	let captured: Arc<Mutex<Vec<WebhookEvent>>> = Arc::new(Mutex::new(Vec::new()));
	let url = capture_server(captured.clone()).await;
	let webhook = Arc::new(Webhook::new_allowing_private(&url, None).expect("webhook"));
	let metrics = Arc::new(Metrics::new());
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = Arc::new(FsSpool::open(dir.path()).expect("spool"));
	let ctx = context(Some(webhook), spool, "mail.example.org".into(), true, true);
	let handle = run(vec![rule(3)], Arc::clone(&metrics), ctx).expect("engine started");
	tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
	metrics.fbl_complaint("alice", "marketing");
	metrics.fbl_complaint("alice", "marketing");
	tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
	handle.stop();
	assert!(captured.lock().expect("lock").is_empty());
}
