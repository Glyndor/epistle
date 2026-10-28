//! Telling the operator how each day went without them checking: a log
//! line, a counter `[[alerts]]` rules can watch, and a `warmup.*` webhook
//! event.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::schedule::{Event, EventKind};

/// The body of a `warmup.ok`, `warmup.held` or `warmup.backoff` event.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WarmupReport {
	/// The receiver group: `gmail`, `outlook`, `yahoo`, `icloud`, `other`.
	pub group: String,
	/// The UTC day judged, `YYYY-MM-DD`.
	pub day: String,
	/// The cap that day; `null` when the group had none.
	pub cap: Option<u32>,
	/// Recipients the warm-up let go that day.
	pub sent: u32,
	/// Recipients a remote of the group answered for.
	pub attempted: u32,
	/// Share of those deferred for rate or reputation, in percent.
	pub deferred_percent: f64,
	/// Share of those that bounced, in percent.
	pub bounced_percent: f64,
	/// Permanent `5.7.x` refusals.
	pub spam_blocks: u32,
	/// `good`, `bad` or `very_bad`.
	pub verdict: String,
	/// The cap for the next day; `null` when the group has none.
	pub next_cap: Option<u32>,
	/// What became of an operator raise on trial: `pending`, `kept` or
	/// `reverted`.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub raise: Option<String>,
	/// The schedule was paused, so the cap did not move.
	#[serde(default)]
	pub paused: bool,
	/// The accounts with the most bad replies that day, most first, so the
	/// operator can act on them (`epistle limits set submission-rate
	/// --tenant`, or the account itself).
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub causes: Vec<super::state::Cause>,
}

/// `part` as a percentage of `whole`, to one decimal.
pub fn percent(part: u32, whole: u32) -> f64 {
	if whole == 0 {
		return 0.0;
	}
	let permille = u64::from(part) * 1000 / u64::from(whole);
	permille as f64 / 10.0
}

impl WarmupReport {
	/// The report of `event`.
	pub fn of(event: &Event) -> Self {
		let record = &event.record;
		WarmupReport {
			group: event.group.label().to_string(),
			day: crate::storage::delivery_log::day_name(record.day),
			cap: record.cap,
			sent: record.sent,
			attempted: record.attempted,
			deferred_percent: percent(record.deferred, record.attempted),
			bounced_percent: percent(record.bounced, record.attempted),
			spam_blocks: record.spam_blocks,
			verdict: record.verdict.label().to_string(),
			next_cap: record.next_cap,
			raise: record.raise.map(|raise| raise.label().to_string()),
			paused: record.paused,
			causes: record.causes.clone(),
		}
	}

	/// The webhook event carrying this report.
	pub fn into_event(self, kind: EventKind) -> crate::webhook::WebhookEvent {
		use crate::webhook::WebhookEvent;
		match kind {
			EventKind::Ok => WebhookEvent::WarmupOk(self),
			EventKind::Held => WebhookEvent::WarmupHeld(self),
			EventKind::Backoff => WebhookEvent::WarmupBackoff(self),
		}
	}
}

/// `account=bad, ...` for a log line.
fn causes(causes: &[super::state::Cause]) -> String {
	let named: Vec<String> = causes
		.iter()
		.map(|cause| format!("{}={}", cause.account, cause.bad))
		.collect();
	named.join(", ")
}

/// Where judged days are reported, besides the log.
#[derive(Default)]
pub struct Notify {
	pub(super) webhook: Option<Arc<crate::webhook::Webhook>>,
	pub(super) metrics: Option<Arc<crate::metrics::Metrics>>,
}

impl Notify {
	/// Report each of `events`. The webhook is advisory and fire-and-forget,
	/// and needs a running Tokio runtime; without one it is skipped.
	pub fn send(&self, events: &[Event]) {
		for event in events {
			let report = WarmupReport::of(event);
			let cap = |cap: Option<u32>| cap.map_or("none".to_string(), |cap| cap.to_string());
			match event.kind {
				EventKind::Ok => tracing::info!(
					group = %report.group, day = %report.day, verdict = %report.verdict,
					cap = %cap(report.cap), next_cap = %cap(report.next_cap), "warm-up day went well"
				),
				EventKind::Held | EventKind::Backoff => tracing::warn!(
					group = %report.group, day = %report.day, verdict = %report.verdict,
					cap = %cap(report.cap), next_cap = %cap(report.next_cap),
					deferred_percent = report.deferred_percent, bounced_percent = report.bounced_percent,
					spam_blocks = report.spam_blocks, causes = %causes(&report.causes),
					"warm-up day went badly"
				),
			}
			if let Some(metrics) = &self.metrics {
				match event.kind {
					EventKind::Ok => {}
					EventKind::Held => metrics.warmup_held(),
					EventKind::Backoff => metrics.warmup_backoff(),
				}
			}
			if let Some(webhook) = &self.webhook
				&& let Ok(runtime) = tokio::runtime::Handle::try_current()
			{
				let webhook = Arc::clone(webhook);
				let body = report.into_event(event.kind);
				runtime.spawn(async move { webhook.notify(&body).await });
			}
		}
	}
}

#[cfg(test)]
mod tests;
