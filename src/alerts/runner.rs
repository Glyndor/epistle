//! Background runner: spawns one Tokio task per rule, ticks each one at the
//! rule's `window_secs`, calls the pure [`super::evaluate`] function and
//! dispatches the configured side-effects on a fire.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time::{self, MissedTickBehavior};

use crate::config::Alert;
use crate::dnsbl::own::Listing;
use crate::metrics::Metrics;
use crate::smtp::session::AcceptedMessage;
use crate::storage::FsSpool;
use crate::webhook::{Webhook, WebhookEvent};

use super::{CompiledRule, State, Verdict, evaluate, unix_now};
use crate::smtp::identification::SYSTEM_AUTO_SUBMITTED as SYSTEM;

/// Shared inputs every rule's task needs at fire time. `Arc` so the per-rule
/// task borrows cheap clones.
#[derive(Clone)]
pub struct DispatchContext {
	webhook: Option<Arc<Webhook>>,
	spool: Arc<FsSpool>,
	hostname: String,
	/// Whether the alert emails carry `Auto-Submitted: auto-generated`
	/// (the `system_auto_submitted` switch).
	auto_submitted: bool,
	/// Whether generated mail asks Exchange to suppress automatic responses.
	auto_response_suppress: bool,
}

/// Handle returned by [`run`]. Drop it (or call [`stop`](EngineHandle::stop))
/// to terminate the background tasks. `None` when the config has no rules:
/// no task is spawned, no overhead.
pub struct EngineHandle {
	stop: Option<Arc<Notify>>,
	task: Option<JoinHandle<()>>,
}

impl EngineHandle {
	/// Stop the background engine task. Idempotent: a second call is a no-op.
	pub fn stop(mut self) {
		if let Some(stop) = self.stop.take() {
			stop.notify_waiters();
		}
		if let Some(task) = self.task.take() {
			task.abort();
		}
	}
}

/// Spawn the alert engine. Returns `None` when the config has no rules: no
/// task, no overhead.
///
/// Each rule runs on its own tokio task with its own [`State`], so two rules
/// cannot starve one another and a slow webhook delivery on one rule does not
/// delay another rule's next sample.
///
/// A rule with `enabled = false` is left out: it has no task, so it samples
/// nothing and cannot fire.
///
/// A rule that fails its compile-time validation is dropped at startup with a
/// warning: the same validation ran at config-load time, so this only happens
/// when rules are added programmatically in tests.
pub fn run(rules: Vec<Alert>, metrics: Arc<Metrics>, ctx: DispatchContext) -> Option<EngineHandle> {
	let compiled: Vec<CompiledRule> = rules
		.iter()
		.filter(|rule| rule.enabled)
		.filter_map(|rule| match CompiledRule::from_alert(rule) {
			Ok(c) => Some(c),
			Err(error) => {
				tracing::warn!(%error, "alert rule dropped at runtime");
				None
			}
		})
		.collect();
	if compiled.is_empty() {
		return None;
	}
	let stop = Arc::new(Notify::new());
	let mut handles = Vec::with_capacity(compiled.len());
	for rule in compiled {
		let metrics = Arc::clone(&metrics);
		let ctx = ctx.clone();
		let stop = Arc::clone(&stop);
		handles.push(tokio::spawn(task_one(rule, metrics, ctx, stop)));
	}
	let task = tokio::spawn(async move {
		for handle in handles {
			let _ = handle.await;
		}
	});
	Some(EngineHandle {
		stop: Some(stop),
		task: Some(task),
	})
}

/// Background loop for one rule. Returns when the shared stop signal fires or
/// the task is cancelled.
async fn task_one(
	rule: CompiledRule,
	metrics: Arc<Metrics>,
	ctx: DispatchContext,
	stop: Arc<Notify>,
) {
	let mut state = State::default();
	let mut ticker = time::interval(Duration::from_secs(rule.window_secs.max(1)));
	ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
	// The first tick fires immediately; treat it as warmup: just record the
	// baseline counter value and skip evaluation. From the second tick on,
	// every interval produces a real delta and a possible fire. The own-IP
	// counter is a transition counter, so its first sample is evaluated
	// against zero and a listing found during startup is not lost.
	if rule.metric == crate::metrics::OWN_IP_BLOCKLISTED {
		state.prev_sample = Some(0);
	} else {
		ticker.tick().await;
		state.prev_sample = Some(metrics.snapshot().get(rule.metric).copied().unwrap_or(0));
	}
	loop {
		let next = stop.notified();
		tokio::select! {
			_ = next => return,
			_ = ticker.tick() => {
				let now_snapshot = metrics.snapshot();
				let now_value = now_snapshot.get(rule.metric).copied().unwrap_or(0);
				let now_unix = unix_now();
				let delta = state
					.prev_sample
					.map(|prev| now_value.saturating_sub(prev))
					.unwrap_or(0);
				state.prev_sample = Some(now_value);
				if evaluate(&rule, &mut state, delta, now_unix) == Verdict::Fire
					&& let Err(error) = dispatch(&rule, &ctx, delta, now_unix, &metrics)
				{
					tracing::warn!(%error, rule = %rule.name, "alert dispatch failed");
				}
			}
		}
	}
}

/// Fire the configured side-effects for a rule that just crossed threshold.
/// Fails open: every error is logged and the engine keeps running.
fn dispatch(
	rule: &CompiledRule,
	ctx: &DispatchContext,
	delta: u64,
	now_unix: u64,
	metrics: &Metrics,
) -> Result<(), super::AlertError> {
	let listings = if rule.metric == crate::metrics::OWN_IP_BLOCKLISTED {
		// The newest `delta` listings are the ones this firing is about; the
		// older ones were announced when they appeared.
		let mut found = metrics.own_ip_listings();
		found.sort_by_key(|listing| std::cmp::Reverse(listing.first_seen));
		found.truncate(usize::try_from(delta).unwrap_or(usize::MAX));
		found
	} else {
		Vec::new()
	};
	if rule.webhook {
		let Some(poster) = ctx.webhook.as_ref() else {
			tracing::warn!(
				rule = %rule.name,
				"alert webhook requested but no webhook is active (the [webhook] section is missing or has enabled = false)"
			);
			return Ok(());
		};
		if rule.metric == crate::metrics::OWN_IP_BLOCKLISTED {
			for listing in &listings {
				let event = WebhookEvent::OwnIpBlocklisted {
					address: listing.address.to_string(),
					zone: listing.zone.clone(),
					delist_url: listing.delist_url.clone(),
				};
				let poster = Arc::clone(poster);
				tokio::spawn(async move { poster.notify(&event).await });
			}
		} else {
			let event = WebhookEvent::MetricAlert {
				name: rule.name.clone(),
				metric: rule.metric.to_string(),
				value: delta,
				threshold: rule.threshold,
				window_secs: rule.window_secs,
			};
			let poster = Arc::clone(poster);
			tokio::spawn(async move { poster.notify(&event).await });
		}
	}
	if !rule.email.is_empty() {
		let message = build_email(
			rule,
			&ctx.hostname,
			delta,
			now_unix,
			ctx.auto_submitted,
			ctx.auto_response_suppress,
			&listings,
		)?;
		// An alert is the operator's own mail: no tenant owns it, so it has no
		// owner and its events use the server-wide webhook.
		ctx.spool
			.store(&message, None, &std::collections::BTreeMap::new())?;
	}
	Ok(())
}

/// Build the alert email as a minimal RFC 5322 plain-text message.
///
/// Subject is fixed (`[epistle] alert: <name>`); the body lists the rule's
/// inputs so the on-call operator has the context to triage without looking
/// at the config. The envelope uses `epistle-alerts@<hostname>` so a failing
/// DSN is delivered back to the server.
fn build_email(
	rule: &CompiledRule,
	hostname: &str,
	delta: u64,
	_now_unix: u64,
	auto_submitted: bool,
	auto_response_suppress: bool,
	listings: &[Listing],
) -> Result<AcceptedMessage, super::AlertError> {
	let from_address = format!("epistle-alerts@{hostname}");
	let from = format!("epistle-alerts <{from_address}>");
	let subject = format!("[epistle] alert: {}", rule.name);
	let date = crate::clock::rfc5322(SystemTime::now());
	let message_id = format!("<{}-alerts@{hostname}>", uuid::Uuid::now_v7());
	let listing_section = if listings.is_empty() {
		String::new()
	} else {
		let lines = listings
			.iter()
			.map(|listing| {
				let link = listing
					.delist_url
					.as_deref()
					.map(|url| format!("; delist: {url}"))
					.unwrap_or_default();
				format!("  {} listed in {}{}", listing.address, listing.zone, link)
			})
			.collect::<Vec<_>>()
			.join("\r\n");
		format!("\r\n Listings:\r\n{lines}\r\n")
	};
	let body = format!(
		"An alert rule fired.\r\n\
		 \r\n\
		 Rule:      {name}\r\n\
		 Metric:    {metric}\r\n\
		 Window:    {window} s\r\n\
		 Delta:     {delta}\r\n\
		 Condition: {op} {threshold}\r\n\
		 {listing_section}\
		 Fired at:  {date}\r\n\
		 \r\n\
		 This message was generated automatically by the alert engine. Check\r\n\
		 the running daemon's logs for the webhook delivery attempt.\r\n",
		name = rule.name,
		metric = rule.metric,
		window = rule.window_secs,
		delta = delta,
		op = op_str(rule.op),
		threshold = rule.threshold,
		listing_section = listing_section,
		date = date,
	);
	let mut auto = if auto_submitted {
		format!("Auto-Submitted: {SYSTEM}\r\n")
	} else {
		String::new()
	};
	auto.push_str(crate::smtp::identification::auto_response_suppress(
		auto_response_suppress,
	));
	let data = format!(
		"From: {from}\r\n\
		 To: {to}\r\n\
		 Subject: {subject}\r\n\
		 Date: {date}\r\n\
		 Message-ID: {message_id}\r\n\
		 {auto}\
		 MIME-Version: 1.0\r\n\
		 Content-Type: text/plain; charset=utf-8\r\n\
		 \r\n\
		 {body}",
		from = from,
		to = rule.email.join(", "),
		subject = subject,
		date = date,
		message_id = message_id,
		auto = auto,
		body = body,
	)
	.into_bytes();
	Ok(AcceptedMessage {
		reverse_path: from_address,
		recipients: rule.email.clone(),
		data,
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: false,
		no_dsn: Vec::new(),
	})
}

fn op_str(op: crate::config::AlertOp) -> &'static str {
	use crate::config::AlertOp;
	match op {
		AlertOp::Ge => ">=",
		AlertOp::Gt => ">",
		AlertOp::Le => "<=",
		AlertOp::Lt => "<",
		AlertOp::Eq => "==",
	}
}

/// `Arc<FsSpool>` is what `serve` already holds. A tiny newtype keeps callers
/// from having to thread the spool + webhook + hostname through every layer.
pub fn context(
	webhook: Option<Arc<Webhook>>,
	spool: Arc<FsSpool>,
	hostname: String,
	auto_submitted: bool,
	auto_response_suppress: bool,
) -> DispatchContext {
	DispatchContext {
		webhook,
		spool,
		hostname,
		auto_submitted,
		auto_response_suppress,
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn auto_response_suppress_controls_the_spooled_alert() {
		for suppress in [false, true] {
			let dir = tempfile::tempdir().expect("tempdir");
			let spool = Arc::new(FsSpool::open(dir.path()).expect("spool"));
			let ctx = context(
				None,
				Arc::clone(&spool),
				"mail.example.org".into(),
				true,
				suppress,
			);
			let alert = Alert {
				name: "bounce-storm".into(),
				metric: "bounced".into(),
				op: crate::config::AlertOp::Ge,
				threshold: 50,
				window_secs: 60,
				cooldown_secs: 60,
				enabled: true,
				webhook: false,
				email: vec!["ops@example.org".into()],
			};
			let rule = CompiledRule::from_alert(&alert).expect("rule");
			dispatch(&rule, &ctx, 60, 1_790_000_000).expect("dispatch");
			let ids = spool.list().expect("list");
			assert_eq!(ids.len(), 1);
			let entry = spool.load(ids[0]).expect("alert");
			let text = String::from_utf8(entry.data).expect("UTF-8");
			let headers = text.split_once("\r\n\r\n").expect("headers").0;
			assert!(headers.contains("Auto-Submitted: auto-generated"));
			assert_eq!(
				headers.contains("X-Auto-Response-Suppress: DR, NDR, RN, NRN, OOF, AutoReply"),
				suppress
			);
		}
	}
}
