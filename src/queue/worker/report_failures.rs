//! Sending the failure report (DSN) of a message: the sink may refuse it, so
//! it is tried again after a growing wait and given up on at a cap.

use super::Worker;
use super::reports::report_recipients;
use crate::storage::RecipientStatus;

impl Worker {
	/// Send the failure report for every failed recipient not reported yet,
	/// then mark them reported. Returns whether there were any.
	///
	/// A report the sink refuses is tried again after a growing wait, up to
	/// [`MAX_REPORT_ATTEMPTS`] times; after that, or when the sink says the
	/// recipient is gone for good, it is given up on and the recipients are
	/// marked reported, so one report cannot be retried for ever.
	pub(super) fn report_failures(&self, id: uuid::Uuid) -> std::io::Result<bool> {
		let entry = self.spool.load(id)?;
		let envelope = &entry.envelope;
		let now = self.now_epoch();
		let unreported: Vec<String> = envelope
			.recipients_in(RecipientStatus::Failed)
			.into_iter()
			.filter(|recipient| !envelope.recipient_state(recipient).reported)
			.collect();
		if unreported.is_empty() {
			return Ok(false);
		}
		if unreported
			.iter()
			.any(|recipient| envelope.recipient_state(recipient).report_after > now)
		{
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
				self.auto_submitted,
			) {
			match self.send_report(id, message, "bounce") {
				ReportOutcome::Queued => {}
				ReportOutcome::Refused => {
					return self.report_refused(id, &unreported, now).map(|_| false);
				}
				ReportOutcome::Gone => {
					tracing::warn!(%id, "the sender of this message no longer exists; its failure report is dropped");
				}
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

	/// Count a refused failure report: wait longer before the next try, or
	/// give up at the cap and say so once.
	fn report_refused(
		&self,
		id: uuid::Uuid,
		unreported: &[String],
		now: u64,
	) -> std::io::Result<()> {
		let mut gave_up = false;
		self.spool.update_envelope(id, |envelope| {
			for recipient in unreported {
				let mut state = envelope.recipient_state(recipient);
				state.report_attempts += 1;
				if state.report_attempts >= MAX_REPORT_ATTEMPTS {
					state.reported = true;
					gave_up = true;
				} else {
					state.report_after = now + report_wait(state.report_attempts);
				}
				envelope.set_recipient_state(recipient, state);
			}
		})?;
		if gave_up {
			tracing::error!(
				%id,
				attempts = MAX_REPORT_ATTEMPTS,
				"the failure report was refused every time; giving up on it"
			);
		}
		Ok(())
	}

	/// Hand a generated report to the bounce sink. A missing sink is a choice
	/// of the configuration and counts as done.
	pub(super) fn send_report(
		&self,
		id: uuid::Uuid,
		message: crate::smtp::session::AcceptedMessage,
		what: &str,
	) -> ReportOutcome {
		match &self.bounce_sink {
			Some(sink) => match sink.deliver_report(message) {
				Ok(()) => ReportOutcome::Queued,
				Err(crate::smtp::sink::SinkError::Gone(error)) => {
					tracing::warn!(%id, %error, what, "report not deliverable: the recipient is gone");
					ReportOutcome::Gone
				}
				Err(error) => {
					tracing::warn!(%id, %error, what, "report delivery failed");
					ReportOutcome::Refused
				}
			},
			None => {
				tracing::warn!(%id, what, "dropping report: no bounce sink configured");
				ReportOutcome::Queued
			}
		}
	}
}

/// How many times a refused failure report is tried before it is given up on.
pub(super) const MAX_REPORT_ATTEMPTS: u32 = 5;

/// Seconds to wait after the `attempts`-th refusal: five minutes, then four
/// times as long each time.
pub(super) fn report_wait(attempts: u32) -> u64 {
	300u64.saturating_mul(4u64.saturating_pow(attempts.saturating_sub(1)))
}

/// What became of a report handed to the sink.
pub(super) enum ReportOutcome {
	/// Queued, or deliberately dropped for want of a sink.
	Queued,
	/// The sink failed in a way that may pass.
	Refused,
	/// The recipient no longer exists: trying again finds the same.
	Gone,
}
