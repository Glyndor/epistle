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

impl Worker {
	/// Write one per-recipient outcome to the delivery log, when the log
	/// is enabled. A best-effort writer: a failed `append` is logged and
	/// otherwise ignored, the same as the webhook and the bounce sink
	/// (mail flow must not be blocked by a logging error). The `reply`
	/// field is truncated to 200 bytes of UTF-8 by the caller; the worker
	/// passes it through unchanged.
	fn log_outcome(
		&self,
		envelope_id: uuid::Uuid,
		envelope_account: Option<&str>,
		envelope_from: &str,
		recipient: &str,
		outcome: DeliveryOutcome,
		remote: Option<&str>,
		reply: Option<&str>,
		attempt: u32,
		extra: &BTreeMap<String, String>,
	) {
		let Some(log) = &self.delivery_log else {
			return;
		};
		let record = DeliveryRecord {
			time: self.now_epoch(),
			spool_id: envelope_id,
			account: envelope_account.map(str::to_string),
			from: envelope_from.to_string(),
			recipient: recipient.to_string(),
			outcome,
			remote: remote.filter(|value| !value.is_empty() && *value != "-").map(str::to_string),
			reply: reply.map(str::to_string),
			attempt,
			extra: extra.clone(),
		};
		if let Err(error) = log.append(&record) {
			tracing::warn!(%envelope_id, %error, "delivery log write failed");
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

	/// The recipients of `entry` due at `now`, minus those on a suppression
	/// list (globally or for the sending account). Those hard-bounced before:
	/// they are recorded as failed with no second report, and never contacted.
	pub(super) fn skip_suppressed(
		&self,
		id: uuid::Uuid,
		entry: &SpoolEntry,
		now: u64,
	) -> std::io::Result<Vec<String>> {
		let due = entry.envelope.due(now);
		let Some(suppression) = &self.suppression else {
			return Ok(due);
		};
		let account = &entry.envelope.reverse_path;
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
				}
				envelope.settle();
			})?;
			for recipient in &skipped {
				self.log_outcome(
					id,
					entry.envelope.account.as_deref(),
					&entry.envelope.reverse_path,
					recipient,
					DeliveryOutcome::Suppressed,
					None,
					Some("recipient is on the suppression list"),
					0,
					&entry.envelope.extra,
				);
				self.notify_suppressed(id, recipient, &entry.envelope.extra);
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
		let remote = conversation.remote.as_deref().unwrap_or("-");
		let message_id = message_id_of(entry);
		for (recipient, result) in &conversation.results {
			match result {
				Ok(()) => {
					tracing::debug!(%id, %recipient, remote, "delivered");
					self.log_outcome(
						id,
						entry.envelope.account.as_deref(),
						&entry.envelope.reverse_path,
						recipient,
						DeliveryOutcome::Delivered,
						Some(remote),
						Some("250 OK"),
						0,
						&entry.envelope.extra,
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
					let attempts = entry.envelope.recipient_state(recipient).attempts;
					tracing::debug!(%id, %recipient, remote, class, %reason, "delivery deferred");
					self.log_outcome(
						id,
						entry.envelope.account.as_deref(),
						&entry.envelope.reverse_path,
						recipient,
						DeliveryOutcome::Deferred,
						Some(remote),
						Some(&Self::bounded_reply(reason)),
						attempts,
						&entry.envelope.extra,
					);
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
					self.log_outcome(
						id,
						entry.envelope.account.as_deref(),
						&entry.envelope.reverse_path,
						recipient,
						DeliveryOutcome::Failed,
						Some(remote),
						Some(&Self::bounded_reply(reason)),
						entry.envelope.recipient_state(recipient).attempts,
						&entry.envelope.extra,
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
	fn notify_suppressed(
		&self,
		id: uuid::Uuid,
		recipient: &str,
		extra: &BTreeMap<String, String>,
	) {
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
				envelope.set_recipient_state(recipient, state);
			}
			envelope.settle();
		})?;
		for recipient in pending {
			let state = envelope.recipient_state(recipient);
			let reason = state.last_error.as_deref().unwrap_or_default();
			let class = classify_reason(reason, false).class.label();
			let remote = state.remote.as_deref().unwrap_or("-");
			tracing::warn!(%id, %recipient, remote, class, %reason, "giving up: message expired");
			self.log_outcome(
				id,
				envelope.account.as_deref(),
				&envelope.reverse_path,
				recipient,
				DeliveryOutcome::Failed,
				state.remote.as_deref(),
				Some(&Self::bounded_reply(reason)),
				state.attempts,
				&envelope.extra,
			);
			self.notify_failed(
				id,
				recipient,
				reason,
				state.remote.clone(),
				&envelope.extra,
			);
		}
		Ok(())
	}

	/// Send the failure report for every failed recipient not reported yet,
	/// then mark them reported. Returns whether there were any.
	pub(super) fn report_failures(&self, id: uuid::Uuid) -> std::io::Result<bool> {
		let entry = self.spool.load(id)?;
		let envelope = &entry.envelope;
		let unreported: Vec<String> = envelope
			.recipients_in(RecipientStatus::Failed)
			.into_iter()
			.filter(|recipient| !envelope.recipient_state(recipient).reported)
			.collect();
		if unreported.is_empty() {
			return Ok(false);
		}
		// Recipients with NOTIFY=NEVER get no failure DSN (RFC 3461). The
		// others share one report, each with its own status and reply.
		let recipients = report_recipients(envelope, &unreported);
		if !recipients.is_empty()
			&& let Some(message) = crate::queue::bounce::build_failed(
				&self.ehlo_hostname,
				&envelope.reverse_path,
				&recipients,
				&entry.data,
				std::time::SystemTime::now(),
			) {
			self.send_report(id, message, "bounce");
		}
		self.spool.update_envelope(id, |envelope| {
			for recipient in &unreported {
				let mut state = envelope.recipient_state(recipient);
				state.reported = true;
				envelope.set_recipient_state(recipient, state);
			}
		})?;
		Ok(true)
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
			) {
			self.send_report(id, message, "delay warning");
		}
		// Mark warned regardless, so it is attempted at most once.
		if let Err(error) = self.spool.mark_delay_warned(id) {
			tracing::warn!(%id, %error, "failed to record delay warning");
		}
	}

	/// Hand a generated report to the bounce sink.
	fn send_report(
		&self,
		id: uuid::Uuid,
		message: crate::smtp::session::AcceptedMessage,
		what: &str,
	) {
		match &self.bounce_sink {
			Some(sink) => {
				if let Err(error) = sink.deliver(message) {
					tracing::warn!(%id, %error, what, "report delivery failed");
				}
			}
			None => tracing::warn!(%id, what, "dropping report: no bounce sink configured"),
		}
	}
}

/// The report lines for `recipients`, leaving out those that asked for no
/// DSN (`NOTIFY=NEVER`, RFC 3461).
fn report_recipients(
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
