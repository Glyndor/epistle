//! Outbound event webhooks (JSON over HTTPS).
//!
//! Delivers small JSON event notifications to a configured endpoint, optionally
//! HMAC-SHA256 signed. Webhooks are advisory and fail open: a delivery error is
//! logged and never blocks mail processing.

use std::time::Duration;

use serde::Serialize;

/// A delivery event worth notifying about. Serializes to the POST body.
#[derive(Debug, Clone, Serialize)]
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
		/// The failure reason (remote response or local error).
		reason: String,
	},
}

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
		let mut request = self
			.client
			.post(&self.url)
			.header(reqwest::header::CONTENT_TYPE, "application/json");
		if let Some(secret) = &self.secret {
			request = request.header("X-Webhook-Signature", sign(secret, &body));
		}
		match request.body(body).send().await {
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
