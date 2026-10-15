use super::*;
use crate::queue::warmup::Group;
use crate::queue::warmup::policy::Verdict;
use crate::queue::warmup::state::{DayRecord, RaiseOutcome};

fn event(kind: EventKind, verdict: Verdict, raise: Option<RaiseOutcome>) -> Event {
	Event {
		kind,
		group: Group::Gmail,
		record: DayRecord {
			day: 20_375,
			cap: Some(200),
			sent: 200,
			attempted: 180,
			deferred: 9,
			bounced: 1,
			spam_blocks: 0,
			verdict,
			next_cap: Some(50),
			raise,
			paused: false,
		},
	}
}

#[test]
fn each_kind_is_its_own_webhook_event() {
	let body = |event: &Event| {
		serde_json::to_string(&WarmupReport::of(event).into_event(event.kind)).expect("json")
	};
	assert_eq!(
		body(&event(
			EventKind::Backoff,
			Verdict::Bad,
			Some(RaiseOutcome::Reverted)
		)),
		concat!(
			r#"{"event":"warmup.backoff","group":"gmail","day":"2025-10-14","cap":200,"sent":200,"#,
			r#""attempted":180,"deferred_percent":5.0,"bounced_percent":0.5,"spam_blocks":0,"#,
			r#""verdict":"bad","next_cap":50,"raise":"reverted","paused":false}"#
		)
	);
	let ok = body(&event(EventKind::Ok, Verdict::Good, None));
	assert!(
		ok.starts_with(r#"{"event":"warmup.ok","group":"gmail""#),
		"{ok}"
	);
	assert!(!ok.contains("raise"), "{ok}");
	let held = body(&event(EventKind::Held, Verdict::Bad, None));
	assert!(held.starts_with(r#"{"event":"warmup.held","#), "{held}");
	let back: crate::webhook::WebhookEvent = serde_json::from_str(&held).expect("parses back");
	assert!(
		matches!(back, crate::webhook::WebhookEvent::WarmupHeld(report) if report.verdict == "bad")
	);
}

#[test]
fn percentages_are_exact_to_a_tenth() {
	assert_eq!(percent(0, 0), 0.0);
	assert_eq!(percent(1, 3), 33.3);
	assert_eq!(percent(2, 3), 66.6);
	assert_eq!(percent(1, 1000), 0.1);
	assert_eq!(percent(u32::MAX, u32::MAX), 100.0);
}

#[test]
fn bad_days_count_for_alert_rules() {
	let metrics = Arc::new(crate::metrics::Metrics::new());
	let notify = Notify {
		webhook: None,
		metrics: Some(Arc::clone(&metrics)),
	};
	notify.send(&[
		event(EventKind::Ok, Verdict::Good, None),
		event(EventKind::Held, Verdict::Bad, None),
		event(EventKind::Backoff, Verdict::VeryBad, None),
		event(
			EventKind::Backoff,
			Verdict::Bad,
			Some(RaiseOutcome::Reverted),
		),
	]);
	let snapshot = metrics.snapshot();
	assert_eq!(
		(snapshot["warmup_held"], snapshot["warmup_backoff"]),
		(1, 2)
	);
}
