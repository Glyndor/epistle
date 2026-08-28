//! Alert engine: sample metrics on a window, evaluate rules, fire webhooks or
//! email when the configured condition holds.
//!
//! The engine is split in two so it stays testable:
//!
//! - [`evaluate`] is a pure function — no clocks, no I/O — that takes the
//!   per-window delta, the current time, the rule, and a mutable [`State`],
//!   and returns whether the rule should fire this tick. The sibling
//!   `engine_tests.rs` exercises every branch of this function directly.
//! - [`runner::run`] is the Tokio task spawned from `serve`: it owns the
//!   snapshot/window/cooldown bookkeeping, calls [`evaluate`] every tick,
//!   and on a fire posts a `WebhookEvent::MetricAlert` and/or queues an
//!   email through the outbound spool.
//!
//! Hysteresis: a fired rule will not fire again until `cooldown_secs` have
//! elapsed **and** the condition has stopped holding for at least one tick.
//! Without the second half, a sustained "queue high" alert would page every
//! window.

mod runner;

use std::time::{SystemTime, UNIX_EPOCH};

use thiserror::Error;

use crate::config::{Alert, AlertOp};

pub use runner::{DispatchContext, EngineHandle, context, run};

/// Why a fire failed to dispatch. Logging-only: every error is recoverable
/// (the engine keeps running) so this never propagates out of the runner.
#[derive(Debug, Error)]
pub enum AlertError {
	/// The spool was not registered, but a rule asked to send email.
	#[error("alert email spool is not available")]
	NoSpool,
	/// Serializing the email body failed.
	#[error("alert payload build failed: {0}")]
	Build(String),
	/// Storing the alert email in the outbound spool failed.
	#[error("alert email spool failed: {0}")]
	Spool(#[from] std::io::Error),
}

/// Internal, engine-side view of one configured rule.
///
/// Decoupled from the `Config`-side [`Alert`] so the engine cannot accidentally
/// surface a `Vec<String>` of email recipients or a `String` metric name that
/// has not been checked against the canonical counter list.
#[derive(Debug, Clone)]
pub struct CompiledRule {
	/// Operator-chosen identifier (the `name` from the TOML).
	name: String,
	/// Counter name validated against [`crate::metrics::metric_names`].
	metric: &'static str,
	/// How to compare the windowed delta to `threshold`.
	op: AlertOp,
	/// Right-hand side of `op`.
	threshold: u64,
	/// Sample interval. The task re-evaluates once every `window_secs`.
	window_secs: u64,
	/// Minimum seconds between two fires of this rule.
	cooldown_secs: u64,
	/// Whether to emit a webhook event on fire.
	webhook: bool,
	/// Email recipients on fire (one message per address; sent through the
	/// outbound spool).
	email: Vec<String>,
}

impl CompiledRule {
	/// Build a [`CompiledRule`] from a [`Alert`]. The metric name is checked
	/// against the canonical counter list; unknown names return an error
	/// rather than silently producing an always-hold rule.
	pub fn from_alert(alert: &Alert) -> Result<Self, String> {
		let metric = crate::metrics::metric_names()
			.into_iter()
			.find(|name| *name == alert.metric)
			.ok_or_else(|| format!("unknown metric \"{}\"", alert.metric))?;
		Ok(Self {
			name: alert.name.clone(),
			metric,
			op: alert.op,
			threshold: alert.threshold,
			window_secs: alert.window_secs,
			cooldown_secs: alert.cooldown_secs,
			webhook: alert.webhook,
			email: alert.email.clone(),
		})
	}

	#[cfg(test)]
	fn for_test(
		metric: &'static str,
		op: AlertOp,
		threshold: u64,
		window_secs: u64,
		cooldown_secs: u64,
	) -> Self {
		Self {
			name: format!("test-{metric}"),
			metric,
			op,
			threshold,
			window_secs,
			cooldown_secs,
			webhook: false,
			email: Vec::new(),
		}
	}
}

/// Mutable state for one rule, tracked across ticks.
#[derive(Debug, Clone, Default)]
pub struct State {
	/// Unix seconds of the last fire, or `None` if the rule has never fired.
	last_fire_unix: Option<u64>,
	/// Whether the condition held at the previous evaluation. Exposed for
	/// tests; not used by the hysteresis decision (see `broke_since_fire`).
	last_condition_true: bool,
	/// True once the condition has been observed to be false at any point
	/// since the last fire. Cleared on every fire. The hysteresis gate
	/// requires this to be true before the cooldown is allowed to expire
	/// into another fire.
	broke_since_fire: bool,
	/// Previous snapshot of the watched counter. The first tick records the
	/// baseline and skips evaluation; every subsequent tick compares the
	/// current value against this one.
	prev_sample: Option<u64>,
}

impl State {
	/// Fresh, empty state. Useful from tests; the runner constructs it inline.
	pub fn new() -> Self {
		Self::default()
	}

	/// Unix seconds of the last fire, if any. Exposed for tests and the
	/// runner's bookkeeping.
	pub fn last_fire_unix(&self) -> Option<u64> {
		self.last_fire_unix
	}

	/// Whether the condition held at the previous evaluation. Exposed for
	/// tests of the cooldown gate.
	pub fn last_condition_true(&self) -> bool {
		self.last_condition_true
	}

	/// Whether the condition has been false at least once since the last fire.
	/// Exposed for tests of the hysteresis gate.
	pub fn broke_since_fire(&self) -> bool {
		self.broke_since_fire
	}
}

/// Whether the rule fires this tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
	/// The rule fires: the webhook/email should be dispatched.
	Fire,
	/// The rule does not fire this tick.
	Hold,
}

/// Evaluate a rule against the observed delta. Pure: no I/O, no clocks.
///
/// `state` is updated in place to record the previous fire time and whether
/// the condition has been false at least once since the last fire. The caller
/// advances `state.prev_sample` separately (so it can drive the "warmup" rule
/// where the first sample is just recorded and never compared against).
pub fn evaluate(rule: &CompiledRule, state: &mut State, delta: u64, now_unix: u64) -> Verdict {
	let condition = compare(rule.op, delta, rule.threshold);
	let should_fire = if condition {
		match state.last_fire_unix {
			None => true,
			Some(last) => {
				// Two gates: cooldown elapsed AND the condition has been false
				// at least once between the previous fire and now. `broke_since_fire`
				// latches true on the first false observation after a fire and is
				// only cleared by the next fire, so a sustained-true rule cannot
				// re-fire the instant the cooldown expires.
				now_unix.saturating_sub(last) >= rule.cooldown_secs && state.broke_since_fire
			}
		}
	} else {
		false
	};
	state.last_condition_true = condition;
	if !condition {
		state.broke_since_fire = true;
	}
	if should_fire {
		state.last_fire_unix = Some(now_unix);
		state.broke_since_fire = false;
		Verdict::Fire
	} else {
		Verdict::Hold
	}
}

fn compare(op: AlertOp, value: u64, threshold: u64) -> bool {
	match op {
		AlertOp::Ge => value >= threshold,
		AlertOp::Gt => value > threshold,
		AlertOp::Le => value <= threshold,
		AlertOp::Lt => value < threshold,
		AlertOp::Eq => value == threshold,
	}
}

/// Unix seconds since the epoch, clamped at zero on platforms where the
/// system clock can run backwards.
fn unix_now() -> u64 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0)
}

// Re-export the metrics/spool/webhook types the runner uses so callers of the
// engine do not need to depend on them directly.
#[cfg(test)]
#[path = "engine_tests.rs"]
mod engine_tests;

#[cfg(test)]
#[path = "integration_tests.rs"]
mod integration_tests;
