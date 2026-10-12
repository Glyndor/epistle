//! What the worker does with the outcome of a recipient: suppression, the
//! failure webhook, the failure report (DSN) and the delay warning.

use super::Worker;
use super::conversation::Conversation;
use crate::queue::client::DeliveryError;
use crate::queue::reply::{FailureClass, classify_reason};
use crate::storage::{RecipientStatus, SpoolEntry};

impl Worker {
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
		for (recipient, result) in &conversation.results {
			match result {
				Ok(()) => tracing::debug!(%id, %recipient, remote, "delivered"),
				Err(DeliveryError::Transient(reason)) => {
					tracing::debug!(%id, %recipient, remote, %reason, "delivery deferred");
				}
				Err(DeliveryError::Permanent(reason)) => {
					tracing::warn!(%id, %recipient, remote, %reason, "delivery failed");
					if classify_reason(reason, true).class == FailureClass::PolicyRejected {
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
					self.suppress(&entry.envelope.reverse_path, recipient);
					self.notify_failed(recipient, reason);
				}
			}
		}
	}

	/// Record `recipient` on the suppression lists, global and the sending
	/// account's, so future mail to it is not even attempted.
	fn suppress(&self, account: &str, recipient: &str) {
		if let Some(suppression) = &self.suppression {
			suppression.suppress(recipient);
			if !account.is_empty() {
				suppression.suppress_for(account, recipient);
			}
		}
	}

	/// Fire the advisory delivery-failure webhook for one recipient.
	fn notify_failed(&self, recipient: &str, reason: &str) {
		if let Some(webhook) = &self.webhook {
			let webhook = webhook.clone();
			let event = crate::webhook::WebhookEvent::DeliveryFailed {
				recipient: recipient.to_string(),
				reason: reason.to_string(),
			};
			tokio::spawn(async move { webhook.notify(&event).await });
		}
	}

	/// Give up on the pending recipients of an expired message: each fails
	/// with the last reason it was deferred for.
	pub(super) fn expire(&self, id: uuid::Uuid, pending: &[String]) -> std::io::Result<()> {
		let envelope = self.spool.update_envelope(id, |envelope| {
			for recipient in pending {
				let mut state = envelope.recipient_state(recipient);
				state.status = RecipientStatus::Failed;
				if state.last_error.is_none() {
					state.last_error = Some("message expired in the queue".into());
				}
				envelope.set_recipient_state(recipient, state);
			}
			envelope.settle();
		})?;
		for recipient in pending {
			let reason = envelope.recipient_state(recipient).last_error;
			let reason = reason.as_deref().unwrap_or_default();
			tracing::warn!(%id, %recipient, %reason, "giving up: message expired");
			self.notify_failed(recipient, reason);
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
		// Recipients with NOTIFY=NEVER get no failure DSN (RFC 3461).
		let mut by_reason: std::collections::BTreeMap<String, Vec<String>> = Default::default();
		for recipient in unreported.iter().filter(|r| !envelope.no_dsn.contains(r)) {
			let reason = envelope.recipient_state(recipient).last_error;
			by_reason
				.entry(reason.unwrap_or_default())
				.or_default()
				.push(recipient.clone());
		}
		for (reason, recipients) in by_reason {
			if let Some(message) = crate::queue::bounce::build(
				&self.ehlo_hostname,
				&envelope.reverse_path,
				&recipients,
				&reason,
				&entry.data,
				std::time::SystemTime::now(),
			) {
				self.send_report(id, message, "bounce");
			}
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
		let reason = envelope.last_error.clone().unwrap_or_default();
		// NOTIFY=DELAY is not modelled separately; reuse the failure opt-out so a
		// sender that wants no DSNs at all gets no delay warning either.
		let recipients: Vec<String> = envelope
			.recipients
			.iter()
			.filter(|r| !envelope.no_dsn.contains(r))
			.cloned()
			.collect();
		if !recipients.is_empty()
			&& let Some(message) = crate::queue::bounce::build_delay_warning(
				&self.ehlo_hostname,
				&envelope.reverse_path,
				&recipients,
				&reason,
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
