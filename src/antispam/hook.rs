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
}

type ScanFuture<'a> = Pin<Box<dyn Future<Output = HookVerdict> + Send + 'a>>;

/// A scanner that judges a raw message. Implementations must fail open.
pub trait MailHook: Send + Sync {
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
mod tests {
	use super::*;

	#[test]
	fn parses_known_actions() {
		assert_eq!(
			parse_verdict(br#"{"action":"reject"}"#),
			HookVerdict::Reject
		);
		assert_eq!(
			parse_verdict(br#"{"action":"quarantine"}"#),
			HookVerdict::Quarantine
		);
		assert_eq!(
			parse_verdict(br#"{"action":"junk"}"#),
			HookVerdict::Quarantine
		);
		assert_eq!(
			parse_verdict(br#"{"action":"accept"}"#),
			HookVerdict::Accept
		);
		// Case-insensitive.
		assert_eq!(
			parse_verdict(br#"{"action":"REJECT"}"#),
			HookVerdict::Reject
		);
	}

	#[test]
	fn unknown_or_malformed_fails_open() {
		assert_eq!(
			parse_verdict(br#"{"action":"explode"}"#),
			HookVerdict::Accept
		);
		assert_eq!(parse_verdict(b"not json"), HookVerdict::Accept);
		assert_eq!(parse_verdict(b""), HookVerdict::Accept);
	}

	struct StubHook(HookVerdict);
	impl MailHook for StubHook {
		fn scan(&self, _raw: &[u8]) -> ScanFuture<'_> {
			let verdict = self.0;
			Box::pin(async move { verdict })
		}
	}

	#[tokio::test]
	async fn trait_object_returns_verdict() {
		let hook: Box<dyn MailHook> = Box::new(StubHook(HookVerdict::Quarantine));
		assert_eq!(hook.scan(b"msg").await, HookVerdict::Quarantine);
	}
}
