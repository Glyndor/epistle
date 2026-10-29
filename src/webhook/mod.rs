//! Outbound event webhooks (JSON over HTTPS).
//!
//! Delivers small JSON event notifications to a configured endpoint, optionally
//! HMAC-SHA256 signed. Webhooks are advisory and fail open: a delivery error is
//! logged and never blocks mail processing.

use std::collections::BTreeMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

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
		/// Spool id of the message this recipient belongs to.
		#[serde(default)]
		spool_id: Option<Uuid>,
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
		/// Caller-supplied correlation map (the `extra` object of
		/// `POST /api/v1/send`). `BTreeMap` so the JSON is stable.
		#[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
		extra: BTreeMap<String, String>,
	},
	/// Outbound delivery to a recipient succeeded: the remote server
	/// accepted the message for delivery.
	Delivered {
		/// Spool id of the message this recipient belongs to.
		spool_id: Uuid,
		/// The recipient that accepted the message.
		recipient: String,
		/// The `Message-ID` of the message, when one was assigned before
		/// the queue picked the message up.
		#[serde(default)]
		message_id: Option<String>,
		/// The remote host that gave the success reply.
		#[serde(default)]
		remote: Option<String>,
		/// Caller-supplied correlation map.
		#[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
		extra: BTreeMap<String, String>,
	},
	/// Outbound delivery to a recipient hit a temporary failure that will
	/// be retried. Sent at most once per recipient per message so retries
	/// do not spam the endpoint.
	Delayed {
		/// Spool id of the message this recipient belongs to.
		spool_id: Uuid,
		/// The recipient that was deferred.
		recipient: String,
		/// The remote reply that caused the deferral, or the local reason
		/// when no server answered.
		reason: String,
		/// The remote host, when one answered.
		#[serde(default)]
		remote: Option<String>,
		/// The attempt that produced the deferral.
		attempt: u32,
		/// Caller-supplied correlation map.
		#[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
		extra: BTreeMap<String, String>,
	},
	/// A recipient was on the suppression list, so the queue did not even
	/// try to deliver to them.
	Suppressed {
		/// Spool id of the message this recipient belongs to.
		spool_id: Uuid,
		/// The recipient that was suppressed.
		recipient: String,
		/// Caller-supplied correlation map.
		#[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
		extra: BTreeMap<String, String>,
	},
	/// An operator removed the queue entry before the recipient reached
	/// any other outcome. Sent once per pending recipient.
	Canceled {
		/// Spool id of the message this recipient belongs to.
		spool_id: Uuid,
		/// The recipient that was canceled.
		recipient: String,
		/// Caller-supplied correlation map.
		#[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
		extra: BTreeMap<String, String>,
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
	/// A DKIM key rotation was withdrawn because the new selector never
	/// showed its key in DNS; the previous key keeps signing.
	DkimRotationFailed {
		/// The selector that was published and withdrawn.
		selector: String,
		/// Why the rotation did not complete.
		reason: String,
	},
	/// The antivirus refused a message one of this server's own accounts
	/// submitted: the account may be compromised and sending malware.
	OutboundVirus {
		/// The account that submitted the message.
		account: String,
		/// The signature the antivirus reported.
		signature: String,
	},
	/// An IP warm-up day went well for a receiver group: its cap grew, a
	/// raise was kept, or the day was too light to grow on.
	#[serde(rename = "warmup.ok")]
	WarmupOk(crate::queue::warmup::WarmupReport),
	/// An IP warm-up day went badly for a receiver group: its cap held.
	#[serde(rename = "warmup.held")]
	WarmupHeld(crate::queue::warmup::WarmupReport),
	/// An IP warm-up day went very badly for a receiver group, or an
	/// operator raise did not hold: its cap went back one step.
	#[serde(rename = "warmup.backoff")]
	WarmupBackoff(crate::queue::warmup::WarmupReport),
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
			// Never follow a redirect: the POST carries the signature and the
			// event, and a 307 would resend both wherever the endpoint (or
			// whoever took it over) points, an internal address included.
			.redirect(reqwest::redirect::Policy::none())
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
			Ok(response) if response.status().is_redirection() => {
				tracing::warn!(status = %response.status(), "webhook endpoint answered with a redirect, which is not followed");
				if let Some(metrics) = &self.metrics {
					metrics.webhook_failed();
				}
			}
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
pub(crate) mod tests;
