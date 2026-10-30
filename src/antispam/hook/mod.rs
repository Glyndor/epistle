//! External scanner hook: hand a message to an HTTP filter (ClamAV/Rspamd
//! behind a small service) and act on its verdict.
//!
//! The hook is advisory and fails open: any transport or parse error yields
//! `Accept`, so a scanner outage never blocks mail. The trait is
//! test-injectable; the real implementation POSTs the raw message over HTTP.

use std::pin::Pin;
use std::time::Duration;

use serde::Deserialize;

/// What the external scanner recommends for a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookVerdict {
	/// Deliver normally.
	Accept,
	/// Reject the message outright.
	Reject,
	/// Accept but quarantine to the Rejects mailbox.
	Quarantine,
	/// The scanner could not judge the message and is configured to hold
	/// it back: answer with a temporary failure so the sender retries.
	Defer,
	/// The scanner cannot take this message and a retry will not change
	/// that (it is over the size clamd accepts), and the operator asked
	/// that nothing pass unscanned: refuse it for good.
	Refuse,
}

type ScanFuture<'a> = Pin<Box<dyn Future<Output = HookVerdict> + Send + 'a>>;

/// A scanner that judges a raw message. Implementations must fail open.
pub trait MailHook: Send + Sync {
	/// Inspect the raw RFC 5322 message bytes and return the verdict to apply.
	/// Implementations that hit any transport or parse failure must return
	/// [`HookVerdict::Accept`] so an outage never blocks mail, unless the
	/// operator asked for [`HookVerdict::Defer`] instead
	/// (`clamd_on_error = "defer"`).
	fn scan(&self, raw: &[u8]) -> ScanFuture<'_>;
}

/// The scanner's JSON response: `{"action": "accept"|"reject"|"quarantine"}`.
#[derive(Deserialize)]
struct HookResponse {
	action: String,
}

/// Parse a scanner response body into a verdict. Unknown actions and malformed
/// bodies are treated as `Accept` (fail open).
pub fn parse_verdict(body: &[u8]) -> HookVerdict {
	match serde_json::from_slice::<HookResponse>(body) {
		Ok(response) => match response.action.to_ascii_lowercase().as_str() {
			"reject" => HookVerdict::Reject,
			"quarantine" | "junk" => HookVerdict::Quarantine,
			_ => HookVerdict::Accept,
		},
		Err(_) => HookVerdict::Accept,
	}
}

/// Real hook: POSTs the raw message to a configured HTTP endpoint.
pub struct HttpHook {
	client: reqwest::Client,
	url: String,
}

impl HttpHook {
	/// Build a hook posting to `url`, with a bounded timeout.
	pub fn new(url: &str) -> Result<Self, reqwest::Error> {
		let client = reqwest::Client::builder()
			.timeout(Duration::from_secs(30))
			.build()?;
		Ok(HttpHook {
			client,
			url: url.to_string(),
		})
	}
}

impl MailHook for HttpHook {
	fn scan(&self, raw: &[u8]) -> ScanFuture<'_> {
		let body = raw.to_vec();
		Box::pin(async move {
			let response = match self.client.post(&self.url).body(body).send().await {
				Ok(response) => response,
				Err(error) => {
					tracing::warn!(%error, "scanner hook request failed; accepting");
					return HookVerdict::Accept;
				}
			};
			match response.bytes().await {
				Ok(bytes) => parse_verdict(&bytes),
				Err(error) => {
					tracing::warn!(%error, "scanner hook read failed; accepting");
					HookVerdict::Accept
				}
			}
		})
	}
}

#[cfg(test)]
mod tests;
