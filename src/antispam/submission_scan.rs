//! The antivirus on mail this server's own accounts send. Every submission
//! (SMTP after AUTH, `/api/v1/send`, JMAP `EmailSubmission/set`) reaches the
//! routing sink through [`MessageSink::submit`], so wrapping that sink is the
//! one place where all three are scanned, for local and remote recipients
//! alike. Mail from elsewhere passes through untouched: it has its own
//! screening in the SMTP connection loop.
//!
//! Only the antivirus and the attachment policy run here: an account's own
//! mail is not subjected to the Bayesian filter, reputation, DNSBL or
//! greylisting.

use std::sync::Arc;

use super::attachments::gate;
use super::attachments::policy::{Action, Policy};
use super::clamd::{ClamdHook, Inspection};
use crate::config::ClamdOnError;
use crate::metrics::Metrics;
use crate::smtp::session::AcceptedMessage;
use crate::smtp::sink::{MessageSink, SinkError};
use crate::webhook::{Webhook, WebhookEvent};

/// Longest signature name echoed back to the sender. clamd's own names are
/// far shorter; the bound keeps an SMTP reply line well under 512 octets.
const MAX_SIGNATURE_CHARS: usize = 120;

/// A sink that scans submissions before handing them on.
pub struct ScanningSink {
	inner: Arc<dyn MessageSink>,
	scanner: Option<worker::Scanner>,
	/// Whether a scan that could not run refuses the submission for now
	/// (`clamd_on_error = "defer"`) instead of letting it through.
	defer_unscanned: bool,
	attachments: Option<Arc<Policy>>,
	/// Caps on concurrent attachment inspections, total and per account.
	gate: Arc<gate::Gate>,
	metrics: Option<Arc<Metrics>>,
	webhook: Option<Arc<Webhook>>,
	/// The threads scans ran on, so a test can tell how many there were.
	#[cfg(test)]
	workers: std::sync::Mutex<std::collections::HashSet<std::thread::ThreadId>>,
}

impl ScanningSink {
	/// The sink the server uses: `inner` wrapped in the scan when
	/// `scan_authenticated` is on and clamd is configured, `inner` itself
	/// otherwise. A detection counts in `metrics` and fires `webhook`.
	/// Fails when the scanner thread cannot be started.
	pub fn wrap(
		scan_authenticated: bool,
		inner: Arc<dyn MessageSink>,
		clamd: Option<Arc<ClamdHook>>,
		metrics: Option<Arc<Metrics>>,
		webhook: Option<Arc<Webhook>>,
	) -> std::io::Result<Arc<dyn MessageSink>> {
		Self::wrap_with_attachments(scan_authenticated, inner, clamd, None, metrics, webhook)
	}

	/// [`ScanningSink::wrap`], with the attachment policy applied to
	/// submissions too. A submission the policy would quarantine or reject
	/// is refused: there is no quarantine for outbound mail. A policy that
	/// cannot refuse anything (`mode = "flag"`) is not applied: nothing is
	/// stamped on outgoing mail, so the inspection would only cost time.
	pub fn wrap_with_attachments(
		scan_authenticated: bool,
		inner: Arc<dyn MessageSink>,
		clamd: Option<Arc<ClamdHook>>,
		attachments: Option<Arc<Policy>>,
		metrics: Option<Arc<Metrics>>,
		webhook: Option<Arc<Webhook>>,
	) -> std::io::Result<Arc<dyn MessageSink>> {
		let attachments = attachments.filter(|policy| policy.can_refuse());
		if !scan_authenticated || (clamd.is_none() && attachments.is_none()) {
			return Ok(inner);
		}
		let defer_unscanned = clamd
			.as_ref()
			.is_some_and(|clamd| clamd.on_error() == ClamdOnError::Defer);
		Ok(Arc::new(ScanningSink {
			inner,
			defer_unscanned,
			scanner: clamd.map(worker::Scanner::start).transpose()?,
			attachments,
			gate: gate::Gate::with_defaults(),
			metrics,
			webhook,
			#[cfg(test)]
			workers: Default::default(),
		}))
	}
}

impl MessageSink for ScanningSink {
	fn deliver(&self, message: AcceptedMessage) -> Result<(), SinkError> {
		self.inner.deliver(message)
	}

	fn submit(
		&self,
		message: AcceptedMessage,
		queue_id: uuid::Uuid,
		account: &str,
		extra: &std::collections::BTreeMap<String, String>,
	) -> Result<(), SinkError> {
		if let Some(policy) = &self.attachments {
			self.check_attachments(policy, &message.data, account)?;
		}
		// An unreachable clamd is counted and recorded for `epistle status`
		// inside the hook; the mail then goes on unscanned or waits for a
		// retry, as `clamd_on_error` says, like inbound mail.
		let inspection = self.scan(&message.data)?;
		if inspection == Inspection::Unscanned && self.defer_unscanned {
			tracing::warn!(
				account = %crate::log_id::account(account),
				"clamd could not scan a submission; asking the client to retry"
			);
			return Err(SinkError::ScanUnavailable);
		}
		// Too large for clamd, and a retry would be just as large: with defer
		// nothing passes unscanned, so the submission is refused for good.
		if inspection == Inspection::Skipped && self.defer_unscanned {
			tracing::warn!(
				account = %crate::log_id::account(account),
				"a submission is too large for clamd; refusing it"
			);
			return Err(SinkError::ScanTooLarge);
		}
		if let Inspection::Infected(signature) = inspection {
			let signature = bounded(&signature);
			tracing::warn!(
				account = %crate::log_id::account(account),
				%signature,
				"antivirus refused a submission; the account may be compromised"
			);
			if let Some(metrics) = &self.metrics {
				metrics.outbound_virus();
			}
			self.notify(account, &signature);
			return Err(SinkError::VirusDetected(signature));
		}
		self.inner.submit(message, queue_id, account, extra)
	}
}

impl ScanningSink {
	/// Apply the attachment policy to a submission. A quarantine or a
	/// reject refuses it, permanently: the same message would be refused
	/// again, so nothing retries it forever.
	fn check_attachments(
		&self,
		policy: &Policy,
		raw: &[u8],
		account: &str,
	) -> Result<(), SinkError> {
		let Some(_permit) = self.gate.try_enter(account) else {
			tracing::warn!(
				account = %crate::log_id::account(account),
				"attachment inspection busy; asking the client to retry"
			);
			return Err(SinkError::ScanUnavailable);
		};
		// A panic in the inspection is a temporary failure for this
		// submission, never one that takes the session or the request with
		// it. The inspection holds no shared state a panic could leave
		// half-changed.
		let decision = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
			off_the_runtime(|| policy.check(raw).1)
		}))
		.map_err(|_| {
			tracing::error!(
				account = %crate::log_id::account(account),
				"attachment inspection failed; asking the client to retry"
			);
			SinkError::ScanUnavailable
		})?;
		let codes: Vec<&str> = decision
			.reasons
			.iter()
			.map(|reason| reason.code())
			.collect();
		match decision.action {
			Action::Reject | Action::Quarantine => {
				tracing::warn!(
					account = %crate::log_id::account(account),
					reasons = %codes.join(","),
					"attachment policy refused a submission"
				);
				Err(SinkError::AttachmentRefused(codes.join(",")))
			}
			Action::Flag => {
				tracing::info!(
					account = %crate::log_id::account(account),
					reasons = %codes.join(","),
					"attachment policy flagged a submission"
				);
				Ok(())
			}
			Action::Deliver => Ok(()),
		}
	}

	/// Scan `raw` and say what clamd found; a full scan queue asks the
	/// client to retry.
	fn scan(&self, raw: &[u8]) -> Result<Inspection, SinkError> {
		let Some(scanner) = &self.scanner else {
			return Ok(Inspection::Clean);
		};
		let (inspection, _worker) = scanner.scan(raw).ok_or(SinkError::ScanUnavailable)?;
		#[cfg(test)]
		if let (Some(worker), Ok(mut workers)) = (_worker, self.workers.lock()) {
			workers.insert(worker);
		}
		Ok(inspection)
	}

	/// Fire the `outbound_virus` webhook in the background. It is
	/// advisory: without a runtime to run it on, it is skipped.
	fn notify(&self, account: &str, signature: &str) {
		let (Some(webhook), Ok(runtime)) = (&self.webhook, tokio::runtime::Handle::try_current())
		else {
			return;
		};
		let webhook = Arc::clone(webhook);
		let event = WebhookEvent::OutboundVirus {
			account: account.to_string(),
			signature: signature.to_string(),
		};
		runtime.spawn(async move { webhook.notify(&event).await });
	}
}

/// Run CPU-bound `work` so it does not hold an async worker: on a
/// multi-threaded runtime the worker hands its other tasks on first. Other
/// callers (a current-thread runtime, plain threads) run it in place.
fn off_the_runtime<T>(work: impl FnOnce() -> T) -> T {
	match tokio::runtime::Handle::try_current().map(|handle| handle.runtime_flavor()) {
		Ok(tokio::runtime::RuntimeFlavor::MultiThread) => tokio::task::block_in_place(work),
		_ => work(),
	}
}

/// `signature`, cut to [`MAX_SIGNATURE_CHARS`] characters.
fn bounded(signature: &str) -> String {
	signature.chars().take(MAX_SIGNATURE_CHARS).collect()
}

#[path = "submission_scan_worker.rs"]
mod worker;

#[cfg(test)]
#[path = "submission_scan_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "submission_scan_tests_attachments.rs"]
mod tests_attachments;

#[cfg(test)]
#[path = "submission_scan_tests_dos.rs"]
mod tests_dos;

#[cfg(test)]
#[path = "submission_scan_tests_runtime.rs"]
mod tests_runtime;

#[cfg(test)]
#[path = "submission_scan_tests_on_error.rs"]
mod tests_on_error;
