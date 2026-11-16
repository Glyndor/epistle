//! External scanner hook: hand a message to an HTTP filter (ClamAV/Rspamd
//! behind a small service) and act on its verdict.
//!
//! The hook is advisory and by default fails open: any transport or parse
//! error yields `Accept`, so a scanner outage never blocks mail. An operator
//! who would rather hold mail back than let it pass unscanned sets
//! `scanner_hook_on_error = "defer"`. The trait is test-injectable; the real
//! implementation POSTs the raw message over HTTP.

use std::pin::Pin;
use std::time::Duration;

use serde::Deserialize;

use crate::config::ClamdOnError;

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
	read_verdict(body).unwrap_or(HookVerdict::Accept)
}

/// The verdict a scanner response body carries, or `None` when the body is
/// not the JSON answer a scanner gives. An action the hook does not know is
/// a verdict (`Accept`), not an error.
fn read_verdict(body: &[u8]) -> Option<HookVerdict> {
	let response = serde_json::from_slice::<HookResponse>(body).ok()?;
	Some(match response.action.to_ascii_lowercase().as_str() {
		"reject" => HookVerdict::Reject,
		"quarantine" | "junk" => HookVerdict::Quarantine,
		_ => HookVerdict::Accept,
	})
}

/// Real hook: POSTs the raw message to a configured HTTP endpoint.
pub struct HttpHook {
	client: reqwest::Client,
	url: String,
	on_error: ClamdOnError,
}

impl HttpHook {
	/// Build a hook posting to `url`, with a bounded timeout of 30 seconds
	/// that accepts the message when the call fails.
	pub fn new(url: &str) -> Result<Self, reqwest::Error> {
		Self::with_options(url, Duration::from_secs(30), ClamdOnError::Accept)
	}

	/// Build a hook posting to `url` that gives the scanner `timeout` to
	/// answer, and does `on_error` when the call fails: the transport
	/// breaks, the deadline passes, the answer is too large or it is not a
	/// verdict.
	pub fn with_options(
		url: &str,
		timeout: Duration,
		on_error: ClamdOnError,
	) -> Result<Self, reqwest::Error> {
		let client = reqwest::Client::builder().timeout(timeout).build()?;
		Ok(HttpHook {
			client,
			url: url.to_string(),
			on_error,
		})
	}

	/// What a failed call does.
	fn failed(&self) -> HookVerdict {
		match self.on_error {
			ClamdOnError::Accept => HookVerdict::Accept,
			ClamdOnError::Defer => HookVerdict::Defer,
		}
	}
}

impl MailHook for HttpHook {
	fn scan(&self, raw: &[u8]) -> ScanFuture<'_> {
		let body = raw.to_vec();
		Box::pin(async move {
			let response = match self.client.post(&self.url).body(body).send().await {
				Ok(response) => response,
				Err(error) => {
					tracing::warn!(%error, on_error = ?self.on_error, "scanner hook request failed");
					return self.failed();
				}
			};
			match read_capped(response).await {
				Some(bytes) => read_verdict(&bytes).unwrap_or_else(|| {
					tracing::warn!(on_error = ?self.on_error, "scanner hook answer is not a verdict");
					self.failed()
				}),
				None => {
					tracing::warn!(on_error = ?self.on_error, "scanner hook answer too large or unreadable");
					self.failed()
				}
			}
		})
	}
}

/// The most a scanner may answer: a verdict is a few bytes of JSON, and the
/// endpoint is a service the mail server trusts to be small, not to be well
/// behaved.
const MAX_ANSWER: usize = 64 * 1024;

/// The body of `response` when it fits [`MAX_ANSWER`], read in pieces so a
/// body without an end is dropped at the cap and never held whole.
async fn read_capped(mut response: reqwest::Response) -> Option<Vec<u8>> {
	if response
		.content_length()
		.is_some_and(|n| n > MAX_ANSWER as u64)
	{
		return None;
	}
	let mut body = Vec::new();
	while let Ok(Some(chunk)) = response.chunk().await {
		if body.len() + chunk.len() > MAX_ANSWER {
			return None;
		}
		body.extend_from_slice(&chunk);
	}
	Some(body)
}

#[cfg(test)]
mod tests;
