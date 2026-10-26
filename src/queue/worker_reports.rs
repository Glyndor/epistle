//! What the worker does with the outcome of a recipient: suppression, the
//! failure webhook, the failure report (DSN) and the delay warning.

use std::collections::BTreeMap;

use super::Worker;
use super::conversation::Conversation;
use crate::queue::bounce::ReportRecipient;
use crate::queue::client::DeliveryError;
use crate::queue::reply::{FailureClass, classify_reason};
use crate::smtp::trace::header_values;
use crate::storage::{DeliveryOutcome, DeliveryRecord, RecipientStatus, SpoolEntry};

/// Extract the `Message-ID:` header from a spooled message, when one
/// is present. None is returned when the message body does not
/// carry the header or when the worker has not loaded the body
/// (the entry is delivered without reading the bytes after the
/// envelope settles).
fn message_id_of(entry: &SpoolEntry) -> Option<String> {
	let value = header_values(&entry.data, "message-id");
	value.into_iter().next()
}

/// The number of the attempt a conversation just made for `recipient`,
/// counting from one: those recorded before it, plus this one.
pub(super) fn attempt_of(entry: &SpoolEntry, recipient: &str) -> u32 {
	entry
		.envelope
		.recipient_state(recipient)
		.attempts
		.saturating_add(1)
}

/// Whether a deferral for `reason` of a recipient now in `state` writes a
/// `deferred` record: when the reply differs from the one before, and the
/// recipient has fewer than [`crate::queue::limits::MAX_DEFERRALS_LOGGED`] already.
/// A destination down for days repeating one reply adds nothing after the
/// first, and one that words every reply differently adds a bounded few.
pub(super) fn logs_deferral(state: &crate::storage::RecipientState, reason: &str) -> bool {
	state.last_error.as_deref() != Some(reason)
		&& state.deferrals_logged < crate::queue::limits::MAX_DEFERRALS_LOGGED
}

impl Worker {
	/// Write one per-recipient outcome to the delivery log, when the log
	/// is enabled. A best-effort writer: a failed `append` is logged and
	/// otherwise ignored, the same as the webhook and the bounce sink
	/// (mail flow must not be blocked by a logging error). The `reply`
	/// field is truncated to 200 bytes of UTF-8 by the caller; the worker
	/// passes it through unchanged.
	fn log_outcome(
		&self,
		envelope: &crate::storage::Envelope,
		recipient: &str,
		outcome: DeliveryOutcome,
		remote: Option<&str>,
		reply: Option<&str>,
		attempt: u32,
	) {
		let Some(log) = &self.delivery_log else {
			return;
		};
		let record = DeliveryRecord {
			time: self.now_epoch(),
			spool_id: envelope.id,
			account: envelope.account.clone(),
			from: envelope.reverse_path.clone(),
			recipient: recipient.to_string(),
			outcome,
			remote: remote
				.filter(|value| !value.is_empty() && *value != "-")
				.map(str::to_string),
			reply: reply.map(str::to_string),
			attempt,
			extra: envelope.extra.clone(),
			class: envelope.class,
		};
		if let Err(error) = log.append(&record) {
			tracing::warn!(id = %envelope.id, %error, "delivery log write failed");
		}
	}

	/// Truncate `reply` to the first 200 bytes of UTF-8 (the first
	/// 200 bytes of the remote SMTP reply line; longer values are not
	/// interesting to log).
	fn bounded_reply(reply: &str) -> String {
		let mut out = String::new();
		for ch in reply.chars() {
			if out.len() + ch.len_utf8() > 200 {
				break;
			}
			out.push(ch);
		}
		out
	}

	/// The `due` recipients of an entry, minus those on a suppression
	/// list (globally or for the sending account). Those hard-bounced before:
	/// they are recorded as failed with no second report, and never contacted.
	pub(super) fn skip_suppressed(
		&self,
		id: uuid::Uuid,
		envelope: &crate::storage::Envelope,
		due: Vec<String>,
	) -> std::io::Result<Vec<String>> {
		let Some(suppression) = &self.suppression else {
			return Ok(due);
		};
		let account = &envelope.reverse_path;
		let (skipped, due): (Vec<String>, Vec<String>) = due.into_iter().partition(|recipient| {
			suppression.is_suppressed(recipient)
				|| suppression.is_suppressed_for(account, recipient)
		});
		if !skipped.is_empty() {
			tracing::debug!(%id, ?skipped, "not delivering to suppressed recipients");
			self.spool.update_envelope(id, |envelope| {
				for recipient in &skipped {
					let mut state = envelope.recipient_state(recipient);
					state.status = RecipientStatus::Failed;
					state.reported = true;
					state.last_error = Some("recipient is on the suppression list".into());
					envelope.set_recipient_state(recipient, state);
					super::evidence::intend(
						envelope,
						&super::evidence::Recorded {
							recipient,
							result: crate::evidence::record::OutcomeKind::Suppressed,
							attempt: 0,
							remote: None,
							reply: Some("recipient is on the suppression list"),
							facts: None,
						},
					);
				}
				envelope.settle();
			})?;
			for recipient in &skipped {
				self.record_outcome(
					envelope,
					super::evidence::Recorded {
						recipient,
						result: crate::evidence::record::OutcomeKind::Suppressed,
						attempt: 0,
						remote: None,
						reply: Some("recipient is on the suppression list"),
						facts: None,
					},
				);
				self.log_outcome(
					envelope,
					recipient,
					DeliveryOutcome::Suppressed,
					None,
					Some("recipient is on the suppression list"),
					0,
				);
				self.notify_suppressed(id, recipient, &envelope.extra);
			}
		}
		Ok(due)
	}

	/// Act on the recipients a conversation failed for good: suppress them
	/// and notify the webhook.
	pub(super) fn after_conversation(
		&self,
		id: uuid::Uuid,
		entry: &SpoolEntry,
		conversation: &Conversation,
	) {
		if conversation.held_until.is_some() {
			// Nothing was attempted: the recipients only wait for a hold.
			return;
		}
		let remote = conversation.remote.as_deref().unwrap_or("-");
		let message_id = message_id_of(entry);
		let retry_now = conversation.retry_now();
		for (recipient, result) in &conversation.results {
			if conversation.capped_for(recipient).is_some() {
				// Over the warm-up cap: not attempted, nothing to report.
				continue;
			}
			if retry_now.contains(recipient) {
				tracing::debug!(%id, %recipient, remote, "left for another transaction");
				continue;
			}
			match result {
				Ok(()) => {
					tracing::debug!(%id, %recipient, remote, "delivered");
					self.record_outcome(
						&entry.envelope,
						super::evidence::Recorded {
							recipient,
							result: crate::evidence::record::OutcomeKind::Delivered,
							attempt: attempt_of(entry, recipient),
							remote: Some(remote),
							reply: None,
							facts: Some(&conversation.facts),
						},
					);
					self.log_outcome(
						&entry.envelope,
						recipient,
						DeliveryOutcome::Delivered,
						Some(remote),
						Some(&Self::bounded_reply(
							conversation.facts.reply.as_deref().unwrap_or("250 OK"),
						)),
						attempt_of(entry, recipient),
					);
					self.notify_delivered(
						id,
						recipient,
						message_id.clone(),
						conversation.remote.clone(),
						&entry.envelope.extra,
					);
				}
				Err(DeliveryError::Transient(reason)) => {
					let class = classify_reason(reason, false).class.label();
					let before = entry.envelope.recipient_state(recipient);
					let attempts = before.attempts;
					tracing::debug!(%id, %recipient, remote, class, %reason, "delivery deferred");
					if logs_deferral(&before, reason) {
						self.log_outcome(
							&entry.envelope,
							recipient,
							DeliveryOutcome::Deferred,
							Some(remote),
							Some(&Self::bounded_reply(reason)),
							attempts.saturating_add(1),
						);
					}
					self.notify_delayed(
						id,
						recipient,
						reason,
						conversation.remote.clone(),
						attempts,
						&entry.envelope.extra,
					);
				}
				Err(DeliveryError::Permanent(reason)) => {
					let verdict = classify_reason(reason, true);
					let class = verdict.class.label();
					tracing::warn!(%id, %recipient, remote, class, %reason, "delivery failed");
					self.record_outcome(
						&entry.envelope,
						super::evidence::Recorded {
							recipient,
							result: crate::evidence::record::OutcomeKind::Bounced,
							attempt: attempt_of(entry, recipient),
							remote: Some(remote),
							reply: Some(reason),
							facts: None,
						},
					);
					self.log_outcome(
						&entry.envelope,
						recipient,
						DeliveryOutcome::Failed,
						Some(remote),
						Some(&Self::bounded_reply(reason)),
						attempt_of(entry, recipient),
					);
					if verdict.class == FailureClass::PolicyRejected {
						// Not the address: the remote does not want mail from
						// us. The operator has to look at the sending side.
						tracing::warn!(
							%id,
							remote,
							%reason,
							"remote refused mail on policy grounds: check the sending \
							 reputation (IP and domain listings, SPF, DKIM, DMARC)"
						);
						self.metric(|m| m.outbound_policy_rejected());
					}
					// Only a reply proving the address bad suppresses it; a
					// policy refusal, a full or disabled mailbox, a message
					// too big say nothing about the address.
					if verdict.suppress {
						self.suppress(&entry.envelope.reverse_path, recipient, reason);
					}
					self.notify_failed(
						id,
						recipient,
						reason,
						conversation.remote.clone(),
						&entry.envelope.extra,
					);
				}
			}
		}
	}

	/// Record `recipient` on the suppression lists, global and the sending
	/// account's, with the reply that proved it bad, so future mail to it is
	/// not even attempted.
	fn suppress(&self, account: &str, recipient: &str, reason: &str) {
		if let Some(suppression) = &self.suppression {
			let now = self.now_epoch();
			suppression.suppress_because(recipient, reason, now);
			if !account.is_empty() {
				suppression.suppress_for_because(account, recipient, reason, now);
			}
		}
	}

	/// Fire the advisory delivery-failure webhook for one recipient, with
	/// the class of the failure and the server that answered.
	fn notify_failed(
		&self,
		id: uuid::Uuid,
		recipient: &str,
		reason: &str,
		remote: Option<String>,
		extra: &BTreeMap<String, String>,
	) {
		if let Some(webhook) = &self.webhook {
			let webhook = webhook.clone();
			let event = crate::webhook::WebhookEvent::DeliveryFailed {
				spool_id: Some(id),
				recipient: recipient.to_string(),
				reason: reason.to_string(),
				class: classify_reason(reason, true).class.label().to_string(),
				remote,
				extra: extra.clone(),
			};
			tokio::spawn(async move { webhook.notify(&event).await });
		}
	}

	/// Fire a `Delivered` webhook for one recipient. The recipient is
	/// the one the remote server accepted; the `message_id` is the
	/// `Message-ID:` of the message (when one was stamped before the
	/// queue took the entry).
	fn notify_delivered(
		&self,
		id: uuid::Uuid,
		recipient: &str,
		message_id: Option<String>,
		remote: Option<String>,
		extra: &BTreeMap<String, String>,
	) {
		let Some(webhook) = &self.webhook else {
			return;
		};
		let webhook = webhook.clone();
		let event = crate::webhook::WebhookEvent::Delivered {
			spool_id: id,
			recipient: recipient.to_string(),
			message_id,
			remote,
			extra: extra.clone(),
		};
		tokio::spawn(async move { webhook.notify(&event).await });
	}

	/// Fire a `Delayed` webhook for one recipient. Sent at most once
	/// per (recipient, message). The caller passes `attempts_before`:
	/// the recipient's `attempts` counter BEFORE this conversation
	/// incremented it. `attempts_before == 0` means "this was the first
	/// attempt that failed transiently" so we fire the event; any later
	/// deferral stays quiet so retries do not spam the endpoint. The
	/// JSON carries `attempt = attempts_before + 1`, the attempt number
	/// that produced the deferral (the first attempt is `1`).
	fn notify_delayed(
		&self,
		id: uuid::Uuid,
		recipient: &str,
		reason: &str,
		remote: Option<String>,
		attempts_before: u32,
		extra: &BTreeMap<String, String>,
	) {
		let Some(webhook) = &self.webhook else {
			return;
		};
		if attempts_before > 0 {
			return;
		}
		let webhook = webhook.clone();
		let event = crate::webhook::WebhookEvent::Delayed {
			spool_id: id,
			recipient: recipient.to_string(),
			reason: reason.to_string(),
			remote,
			attempt: attempts_before + 1,
			extra: extra.clone(),
		};
		tokio::spawn(async move { webhook.notify(&event).await });
	}

	/// Fire a `Suppressed` webhook for one recipient.
	fn notify_suppressed(&self, id: uuid::Uuid, recipient: &str, extra: &BTreeMap<String, String>) {
		let Some(webhook) = &self.webhook else {
			return;
		};
		let webhook = webhook.clone();
		let event = crate::webhook::WebhookEvent::Suppressed {
			spool_id: id,
			recipient: recipient.to_string(),
			extra: extra.clone(),
		};
		tokio::spawn(async move { webhook.notify(&event).await });
	}

	/// Give up on the pending recipients of an expired message: each fails
	/// with the last reason it was deferred for.
	pub(super) fn expire(&self, id: uuid::Uuid, pending: &[String]) -> std::io::Result<()> {
		let envelope = self.spool.update_envelope(id, |envelope| {
			for recipient in pending {
				let mut state = envelope.recipient_state(recipient);
				state.status = RecipientStatus::Failed;
				state.expired = true;
				if state.last_error.is_none() {
					state.last_error = Some("message expired in the queue".into());
				}
				let reason = state.last_error.clone().unwrap_or_default();
				let (attempts, remote) = (state.attempts, state.remote.clone());
				envelope.set_recipient_state(recipient, state);
				super::evidence::intend(
					envelope,
					&super::evidence::Recorded {
						recipient,
						result: crate::evidence::record::OutcomeKind::Expired,
						attempt: attempts,
						remote: remote.as_deref(),
						reply: Some(&reason),
						facts: None,
					},
				);
			}
			envelope.settle();
		})?;
		for recipient in pending {
			let state = envelope.recipient_state(recipient);
			let reason = state.last_error.as_deref().unwrap_or_default();
			let class = classify_reason(reason, false).class.label();
			let remote = state.remote.as_deref().unwrap_or("-");
			tracing::warn!(%id, %recipient, remote, class, %reason, "giving up: message expired");
			self.record_outcome(
				&envelope,
				super::evidence::Recorded {
					recipient,
					result: crate::evidence::record::OutcomeKind::Expired,
					attempt: state.attempts,
					remote: state.remote.as_deref(),
					reply: Some(reason),
					facts: None,
				},
			);
			self.log_outcome(
				&envelope,
				recipient,
				DeliveryOutcome::Failed,
				state.remote.as_deref(),
				Some(&Self::bounded_reply(reason)),
				state.attempts,
			);
			self.notify_failed(id, recipient, reason, state.remote.clone(), &envelope.extra);
		}
		Ok(())
	}

	/// Send the one-time "delivery delayed" warning DSN for a still-queued entry.
	pub(super) fn warn_delayed(&self, id: uuid::Uuid) {
		let Ok(entry) = self.spool.load(id) else {
			return;
		};
		let envelope = &entry.envelope;
		if envelope.delay_warned {
			return;
		}
		// Only the recipients still pending are delayed; NOTIFY=DELAY is not
		// modelled separately, so the failure opt-out also silences this.
		let recipients = report_recipients(envelope, &envelope.pending());
		if !recipients.is_empty()
			&& let Some(message) = crate::queue::bounce::build_delay_warning(
				&self.ehlo_hostname,
				&envelope.reverse_path,
				&recipients,
				&entry.data,
				std::time::SystemTime::now(),
				self.auto_submitted,
			) {
			// The warning is advisory and attempted once, whatever came of it.
			let _ = self.send_report(id, message, "delay warning");
		}
		// Mark warned regardless, so it is attempted at most once.
		if let Err(error) = self.spool.mark_delay_warned(id) {
			tracing::warn!(%id, %error, "failed to record delay warning");
		}
	}
}
/// The report lines for `recipients`, leaving out those that asked for no
/// DSN (`NOTIFY=NEVER`, RFC 3461).
pub(super) fn report_recipients(
	envelope: &crate::storage::Envelope,
	recipients: &[String],
) -> Vec<ReportRecipient> {
	recipients
		.iter()
		.filter(|recipient| !envelope.no_dsn.contains(recipient))
		.map(|recipient| {
			let state = envelope.recipient_state(recipient);
			ReportRecipient {
				recipient: recipient.clone(),
				reason: state.last_error.unwrap_or_default(),
				remote: state.remote,
				expired: state.expired,
			}
		})
		.collect()
}
