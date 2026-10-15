//! Submissions that keep evidence.
//!
//! When every recipient is remote, the acceptance is recorded by the spool
//! itself, between the staged write and the rename that queues the
//! message, over the exact (DKIM-signed) bytes queued. With local
//! recipients the message is delivered before anything is queued, so the
//! acceptance is recorded first, over the bytes as submitted. Either way,
//! for `transactional` mail an acceptance that cannot be written durably
//! refuses the message, and so does a held evidence gate.

use std::cell::Cell;
use std::sync::Arc;

use super::SplitDelivery;
use crate::evidence::MailClass;
use crate::evidence::record::Retention;
use crate::evidence::service::{EvidenceService, Submitted};
use crate::smtp::address::Address;
use crate::smtp::directory::Resolution;
use crate::smtp::session::AcceptedMessage;
use crate::smtp::sink::{SinkError, Submission};
use crate::storage::StoreOptions;

impl SplitDelivery {
	/// Record the evidence of submissions through `service`.
	pub fn with_evidence(mut self, service: Arc<EvidenceService>) -> Self {
		self.evidence = Some(service);
		self
	}

	/// The retention this submission keeps, `None` when it keeps none. A
	/// transactional submission is refused when there is no service or its
	/// gate holds transactional mail.
	pub(super) fn evidence_for(
		&self,
		account: &str,
		message: &AcceptedMessage,
		class: MailClass,
	) -> Result<Option<Retention>, SinkError> {
		let Some(service) = &self.evidence else {
			return match class.evidence_mandatory() {
				true => Err(SinkError::EvidenceUnavailable("no evidence log".into())),
				false => Ok(None),
			};
		};
		if class.evidence_mandatory()
			&& let Some(reason) = service.held()
		{
			return Err(SinkError::EvidenceUnavailable(reason));
		}
		Ok(service.retention(account, &message.reverse_path, class))
	}

	/// Whether every recipient leaves the server.
	fn all_remote(&self, message: &AcceptedMessage) -> bool {
		message.recipients.iter().all(|recipient| {
			Address::parse(recipient).is_ok_and(|address| {
				matches!(
					self.directory.current().resolve(&address),
					Resolution::NotLocal
				)
			})
		})
	}

	pub(super) fn route_with_evidence(
		&self,
		mut message: AcceptedMessage,
		queue_id: uuid::Uuid,
		account: &str,
		submission: &Submission,
		retention: Retention,
	) -> Result<(), SinkError> {
		let Some(service) = self.evidence.clone() else {
			return Err(SinkError::EvidenceUnavailable("no evidence log".into()));
		};
		let class = submission.class;
		if !self.all_remote(&message) {
			let submitted = Submitted {
				spool_id: queue_id,
				account,
				class,
				from: &message.reverse_path,
				recipients: &message.recipients,
				data: &message.data,
			};
			record_or_refuse(service.accept(&submitted, retention), class)?;
			let routed = self.route_classed(
				message,
				queue_id,
				Some(account),
				&submission.extra,
				(class, true),
			);
			if let Err(error) = &routed {
				abandon(&service, queue_id, error);
			}
			return routed;
		}
		self.sign_outbound(&mut message);
		let hook_failed = Cell::new(false);
		let record = |bytes: &[u8]| {
			let submitted = Submitted {
				spool_id: queue_id,
				account,
				class,
				from: &message.reverse_path,
				recipients: &message.recipients,
				data: bytes,
			};
			let recorded = service.accept(&submitted, retention);
			match (&recorded, class.evidence_mandatory()) {
				(Err(_), true) => hook_failed.set(true),
				(Err(error), false) => {
					tracing::warn!(%error, %class, "evidence not recorded; the message is still sent");
					return Ok(());
				}
				_ => {}
			}
			recorded
		};
		let options = StoreOptions {
			account: Some(account),
			extra: &submission.extra,
			class,
			evidence: Some(&record),
		};
		match self.outbound.store_with(&message, queue_id, &options) {
			Ok(_) => Ok(()),
			Err(error) if hook_failed.get() => {
				Err(SinkError::EvidenceUnavailable(error.kind().to_string()))
			}
			Err(error) => {
				let error = SinkError::Unavailable(error.to_string());
				abandon(&service, queue_id, &error);
				Err(error)
			}
		}
	}
}

/// Mandatory evidence that could not be written refuses the message.
fn record_or_refuse(recorded: std::io::Result<()>, class: MailClass) -> Result<(), SinkError> {
	match recorded {
		Ok(()) => Ok(()),
		Err(error) if class.evidence_mandatory() => {
			Err(SinkError::EvidenceUnavailable(error.kind().to_string()))
		}
		Err(error) => {
			tracing::warn!(%error, %class, "evidence not recorded; the message is still sent");
			Ok(())
		}
	}
}

/// Best effort: the acceptance is on record, the message is not queued.
fn abandon(service: &EvidenceService, id: uuid::Uuid, why: &SinkError) {
	let reason = match why {
		SinkError::VirusDetected(_) => "refused by the antivirus",
		SinkError::AttachmentRefused(_) => "refused by the attachment policy",
		SinkError::ScanUnavailable => "the content scan was unavailable",
		SinkError::ScanTooLarge => "too large for the content scan",
		SinkError::EvidenceUnavailable(_) => "evidence unavailable",
		SinkError::Unavailable(_) => "storage unavailable",
	};
	if let Err(error) = service.abandon(id, reason) {
		tracing::warn!(%id, %error, "could not record an abandoned submission");
	}
}

#[cfg(test)]
#[path = "routing_evidence_tests.rs"]
mod tests;
