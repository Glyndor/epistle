//! The antivirus on mail this server's own accounts send. Every submission
//! (SMTP after AUTH, `/api/v1/send`, JMAP `EmailSubmission/set`) reaches the
//! routing sink through [`MessageSink::submit`], so wrapping that sink is the
//! one place where all three are scanned, for local and remote recipients
//! alike. Mail from elsewhere passes through untouched: it has its own
//! screening in the SMTP connection loop.
//!
//! Only the antivirus runs here: an account's own mail is not subjected to
//! the Bayesian filter, reputation, DNSBL or greylisting.

use std::sync::Arc;

use super::clamd::{ClamdHook, Inspection};
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
	clamd: Arc<ClamdHook>,
	metrics: Option<Arc<Metrics>>,
	webhook: Option<Arc<Webhook>>,
}

impl ScanningSink {
	/// The sink the server uses: `inner` wrapped in the scan when
	/// `scan_authenticated` is on and clamd is configured, `inner` itself
	/// otherwise. A detection counts in `metrics` and fires `webhook`.
	pub fn wrap(
		scan_authenticated: bool,
		inner: Arc<dyn MessageSink>,
		clamd: Option<Arc<ClamdHook>>,
		metrics: Option<Arc<Metrics>>,
		webhook: Option<Arc<Webhook>>,
	) -> Arc<dyn MessageSink> {
		match clamd {
			Some(clamd) if scan_authenticated => Arc::new(ScanningSink {
				inner,
				clamd,
				metrics,
				webhook,
			}),
			_ => inner,
		}
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
	) -> Result<(), SinkError> {
		// Fail open like the inbound scan: an unreachable clamd is counted
		// and recorded for `epistle status` inside the hook, and the mail
		// goes on unscanned.
		if let Inspection::Infected(signature) = self.clamd.inspect_blocking(&message.data) {
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
		self.inner.submit(message, queue_id, account)
	}
}

impl ScanningSink {
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

/// `signature`, cut to [`MAX_SIGNATURE_CHARS`] characters.
fn bounded(signature: &str) -> String {
	signature.chars().take(MAX_SIGNATURE_CHARS).collect()
}

#[cfg(test)]
#[path = "submission_scan_tests.rs"]
mod tests;
