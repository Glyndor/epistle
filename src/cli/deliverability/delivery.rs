//! The delivery result of the test message, read back from the delivery log
//! the running server writes, with the remote's answer in plain language.

use std::time::Duration;

use serde::Serialize;
use uuid::Uuid;

use crate::cli::term::sanitize;
use crate::queue::reply::{FailureClass, classify_reason, parse_enhanced, provider_cause};
use crate::storage::{DeliveryLog, DeliveryOutcome, DeliveryRecord};

/// Where the message stands.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(super) struct Delivery {
	/// `delivered`, `deferred`, `failed`, `suppressed`, `canceled`, `queued`
	/// (no record yet) or `unlogged` (the delivery log is off).
	pub state: &'static str,
	/// The remote host that answered, as it announced itself.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub remote: Option<String>,
	/// The remote's answer, as logged.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub reply: Option<String>,
	/// What it means.
	pub explanation: String,
}

impl Delivery {
	/// Whether the message was refused for good: the run exits non-zero.
	pub(super) fn is_failure(&self) -> bool {
		matches!(self.state, "failed" | "suppressed" | "canceled")
	}
}

/// What a failure class means for the operator.
fn class_sentence(class: FailureClass) -> &'static str {
	match class {
		FailureClass::InvalidAddress => {
			"the receiver says the destination address does not exist or cannot take mail"
		}
		FailureClass::MailboxFull => "the destination mailbox is full",
		FailureClass::PolicyRejected => {
			"the receiver refused the message by policy (authentication, reputation or content); that is about this server, not about the address"
		}
		FailureClass::TooBig => "the message is larger than the receiver accepts",
		FailureClass::Other => "the receiver's answer does not point to a known cause",
	}
}

/// The remote's answer in plain language: what class of refusal it is, the
/// enhanced status code (RFC 3463) when it carries one, and the provider
/// cause the queue already recognizes.
pub(super) fn explain_reply(reply: &str, permanent: bool) -> String {
	let verdict = classify_reason(reply, permanent);
	let mut text = class_sentence(verdict.class).to_string();
	let code = reply
		.split_whitespace()
		.nth(1)
		.and_then(parse_enhanced)
		.map(|enhanced| enhanced.to_string());
	if let Some(code) = code {
		text.push_str(&format!(" (enhanced status {code})"));
	}
	if let Some(cause) = provider_cause(reply)
		&& !reply.contains(cause.sentence())
	{
		text.push_str(&format!("; {}", cause.sentence()));
	}
	text
}

fn describe(record: &DeliveryRecord) -> Delivery {
	let reply = record.reply.as_deref().map(sanitize);
	let remote = record.remote.as_deref().map(sanitize);
	let (state, explanation) = match record.outcome {
		DeliveryOutcome::Delivered => (
			"delivered",
			"the receiving server accepted the message; that says it took it, not that it reached the inbox instead of the spam folder".to_string(),
		),
		DeliveryOutcome::Deferred => (
			"deferred",
			format!(
				"the receiver asked to try again later and the queue will retry; {}",
				record
					.reply
					.as_deref()
					.map_or_else(|| "it gave no answer".to_string(), |r| explain_reply(r, false))
			),
		),
		DeliveryOutcome::Failed => (
			"failed",
			record.reply.as_deref().map_or_else(
				|| "delivery failed with no answer from a remote server".to_string(),
				|r| explain_reply(r, true),
			),
		),
		DeliveryOutcome::Suppressed => (
			"suppressed",
			"the destination is on the suppression list, so nothing was sent".to_string(),
		),
		DeliveryOutcome::Canceled => (
			"canceled",
			"the queue entry was removed before it was delivered".to_string(),
		),
	};
	Delivery {
		state,
		remote,
		reply,
		explanation,
	}
}

fn unlogged() -> Delivery {
	Delivery {
		state: "unlogged",
		remote: None,
		reply: None,
		explanation: "the delivery log is off ([storage] delivery_log_days = 0), so the result cannot be read back; the message is queued".to_string(),
	}
}

fn queued(id: Uuid) -> Delivery {
	Delivery {
		state: "queued",
		remote: None,
		reply: None,
		explanation: format!(
			"no delivery record yet: the running server scans the queue every 30 seconds, and a warm-up cap or the receiver may hold the message; read it later with `epistle delivery show {id}`"
		),
	}
}

/// The newest record of `id`, if any.
fn latest(log: &DeliveryLog, id: Uuid) -> std::io::Result<Option<DeliveryRecord>> {
	let mut records = log.list(Some(1000), |record| record.spool_id == id)?;
	records.sort_by_key(|record| record.time);
	Ok(records.pop())
}

/// Wait up to `wait` for the message to reach an outcome, looking every
/// `poll`. A deferral is not an outcome: the wait goes on, and the last
/// deferral is what a timeout reports. With the log off there is nothing to
/// read and no wait.
pub(super) async fn await_result(
	log: &DeliveryLog,
	log_days: u64,
	id: Uuid,
	wait: Duration,
	poll: Duration,
) -> Delivery {
	if log_days == 0 {
		return unlogged();
	}
	let deadline = tokio::time::Instant::now() + wait;
	loop {
		let record = match latest(log, id) {
			Ok(record) => record,
			Err(error) => {
				return Delivery {
					state: "queued",
					remote: None,
					reply: None,
					explanation: format!("the delivery log could not be read: {error}"),
				};
			}
		};
		if let Some(record) = &record
			&& record.outcome != DeliveryOutcome::Deferred
		{
			return describe(record);
		}
		if tokio::time::Instant::now() >= deadline {
			return record.as_ref().map_or_else(|| queued(id), describe);
		}
		tokio::time::sleep(poll).await;
	}
}
