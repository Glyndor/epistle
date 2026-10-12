//! Outbound event webhooks (JSON over HTTPS).
//!
//! Delivers small JSON event notifications to a configured endpoint, optionally
//! HMAC-SHA256 signed. Webhooks are advisory and fail open: a delivery error is
//! logged and never blocks mail processing.

use std::time::Duration;

use serde::{Deserialize, Serialize};

/// A delivery event worth notifying about. Serializes to the POST body.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum WebhookEvent {
	/// A message was accepted for a local recipient.
	MessageReceived {
		/// The local account the message is for.
		account: String,
		/// Envelope sender (`""` for the null reverse-path).
		from: String,
		/// `Subject` header, if present.
		subject: Option<String>,
		/// `Message-ID` header, if present (for receiver-side correlation).
		message_id: Option<String>,
	},
	/// Outbound delivery to a recipient permanently failed (a bounce was queued).
	DeliveryFailed {
		/// The recipient that could not be reached.
		recipient: String,
		/// The failure reason: the remote reply as one line
		/// (`550 5.1.1 ...`), or the local error when no server answered.
		reason: String,
		/// What the failure was about: `invalid_address`, `mailbox_full`,
		/// `policy_rejected`, `too_big` or `other`.
		#[serde(default)]
		class: String,
		/// The server that gave `reason`, when one answered.
		#[serde(default)]
		remote: Option<String>,
	},
	/// A `[[alerts]]` rule crossed its threshold over its sample window.
	MetricAlert {
		/// The rule's configured `name` (the stable identifier operators see
		/// in logs and on the wire).
		name: String,
		/// Counter name the rule watches (e.g. `bounced`).
		metric: String,
		/// Observed delta over the window at fire time.
		value: u64,
		/// The threshold the delta crossed.
		threshold: u64,
		/// The window length in seconds (the rule's `window_secs`).
		window_secs: u64,
	},
	/// Sent only by `epistle webhook test` to check that the endpoint is
	/// reachable and verifies signatures. Receivers should acknowledge it and
	/// otherwise ignore it.
	Test {
		/// Fixed text that says this is a connectivity check, not mail activity.
		message: String,
	},
}

/// The `message` carried by the `test` event.
pub const TEST_MESSAGE: &str = "epistle webhook test: connectivity check, no mail activity";

/// Posts events to a configured endpoint with a bounded timeout.
pub struct Webhook {
	client: reqwest::Client,
	url: String,
	secret: Option<String>,
	metrics: Option<std::sync::Arc<crate::metrics::Metrics>>,
}

impl Webhook {
	/// Build a webhook poster for `url`, optionally signing with `secret`.
	pub fn new(url: &str, secret: Option<String>) -> Result<Self, reqwest::Error> {
		let client = reqwest::Client::builder()
			.timeout(Duration::from_secs(15))
			.build()?;
		Ok(Webhook {
			client,
			url: url.to_string(),
			secret,
			metrics: None,
		})
	}

	/// Record delivery outcomes to these process metrics.
	pub fn with_metrics(mut self, metrics: std::sync::Arc<crate::metrics::Metrics>) -> Self {
		self.metrics = Some(metrics);
		self
	}

	/// The signed POST for a serialized event body.
	fn request(&self, body: Vec<u8>) -> reqwest::RequestBuilder {
		let mut request = self
			.client
			.post(&self.url)
			.header(reqwest::header::CONTENT_TYPE, "application/json");
		if let Some(secret) = &self.secret {
			request = request.header("X-Webhook-Signature", sign(secret, &body));
		}
		request.body(body)
	}

	/// Deliver `event`. Fails open: transport/serialization errors are logged,
	/// never propagated.
	pub async fn notify(&self, event: &WebhookEvent) {
		let body = match serde_json::to_vec(event) {
			Ok(body) => body,
			Err(error) => {
				tracing::warn!(%error, "webhook payload serialization failed");
				return;
			}
		};
		match self.request(body).send().await {
			Ok(_) => {
				if let Some(metrics) = &self.metrics {
					metrics.webhook_sent();
				}
			}
			Err(error) => {
				tracing::warn!(%error, "webhook delivery failed");
				if let Some(metrics) = &self.metrics {
					metrics.webhook_failed();
				}
			}
		}
	}

	/// Post the `test` event and report what the endpoint answered. Unlike
	/// [`Webhook::notify`] this surfaces failures and the HTTP status, and it
	/// does not touch the delivery metrics.
	pub async fn send_test(&self) -> Result<reqwest::StatusCode, reqwest::Error> {
		let event = WebhookEvent::Test {
			message: TEST_MESSAGE.into(),
		};
		let body = serde_json::to_vec(&event).expect("a test event always serializes");
		Ok(self.request(body).send().await?.status())
	}
}

/// `sha256=<hex>` HMAC-SHA256 of `body` under `secret` (GitHub-style).
fn sign(secret: &str, body: &[u8]) -> String {
	let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.as_bytes());
	let tag = ring::hmac::sign(&key, body);
	let hex = tag.as_ref().iter().fold(String::new(), |mut acc, byte| {
		use std::fmt::Write;
		let _ = write!(acc, "{byte:02x}");
		acc
	});
	format!("sha256={hex}")
}

#[cfg(test)]
#[path = "webhook_tests.rs"]
mod tests;
