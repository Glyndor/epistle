//! Outbound event webhooks (JSON over HTTPS).
//!
//! Delivers small JSON event notifications to a configured endpoint, optionally
//! HMAC-SHA256 signed. Webhooks are advisory and fail open: a delivery error is
//! logged and never blocks mail processing.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub(crate) mod destination;
mod endpoint;
mod route;

use endpoint::Endpoint;
pub use route::{account_owner, from_config, single_domain};

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

/// Posts events to the configured endpoints with a bounded timeout: the
/// server-wide one and, for the domains of a tenant that has its own, the
/// tenant's. An event goes to exactly one of them, chosen by the hosted
/// domain it belongs to (see [`Webhook::notify_for`]).
pub struct Webhook {
	/// The server-wide `[webhook]`: where the events of every domain that no
	/// tenant webhook claims go, and the server's own events.
	default: Option<Endpoint>,
	/// Hosted domain (lowercase) to the endpoint of the tenant that owns it.
	/// `None` is a tenant whose webhook is switched off or cannot be used: its
	/// domains' events go nowhere, not to the server-wide webhook.
	tenants: HashMap<String, Option<Arc<Endpoint>>>,
	metrics: Option<Arc<crate::metrics::Metrics>>,
}

/// Why a webhook poster could not be built.
#[derive(Debug)]
pub enum WebhookError {
	/// The transport refused to be built.
	Transport(reqwest::Error),
	/// The destination is one this server may not post to.
	Destination(String),
	/// There is no server-wide webhook to post to.
	NoEndpoint,
}

impl std::fmt::Display for WebhookError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			WebhookError::Transport(error) => write!(f, "{error}"),
			WebhookError::Destination(reason) => write!(f, "{reason}"),
			WebhookError::NoEndpoint => write!(f, "no server-wide webhook is configured"),
		}
	}
}

impl std::error::Error for WebhookError {}

impl WebhookError {
	/// The message with the destination URL left out, for output a person reads.
	pub(crate) fn without_url(self) -> String {
		match self {
			WebhookError::Transport(error) => error.without_url().to_string(),
			other => other.to_string(),
		}
	}

	/// Whether the transport gave up waiting for the endpoint.
	pub fn is_timeout(&self) -> bool {
		matches!(self, WebhookError::Transport(error) if error.is_timeout())
	}

	/// Whether the request could not be built at all.
	pub fn is_builder(&self) -> bool {
		matches!(self, WebhookError::Transport(error) if error.is_builder())
	}
}

impl From<reqwest::Error> for WebhookError {
	fn from(error: reqwest::Error) -> Self {
		WebhookError::Transport(error)
	}
}

/// The poster for the connectivity probe of the `[webhook]` section alone
/// (`epistle webhook test`): the section says whether a private destination
/// is allowed, and the poster follows. It knows no tenant, so code that sends
/// events builds its poster with [`from_config`] instead.
pub(crate) fn probe_poster(section: &crate::config::Webhook) -> Result<Webhook, WebhookError> {
	Endpoint::from_section(section).map(Webhook::with_default)
}

impl Webhook {
	/// Build a webhook poster for `url`, optionally signing with `secret`.
	///
	/// A destination inside the networks this host belongs to is refused:
	/// the endpoint is operator-chosen, but the address it names may be
	/// one the host must not reach on its own. Use
	/// [`Webhook::new_allowing_private`] when that is what the operator
	/// asked for.
	pub fn new(url: &str, secret: Option<String>) -> Result<Self, WebhookError> {
		Endpoint::build(url, secret, false).map(Self::with_default)
	}

	/// Build a webhook poster that may post to a private destination, for
	/// an operator who says so in the configuration.
	pub fn new_allowing_private(url: &str, secret: Option<String>) -> Result<Self, WebhookError> {
		Endpoint::build(url, secret, true).map(Self::with_default)
	}

	fn with_default(endpoint: Endpoint) -> Self {
		Webhook {
			default: Some(endpoint),
			tenants: HashMap::new(),
			metrics: None,
		}
	}

	/// Record delivery outcomes to these process metrics.
	pub fn with_metrics(mut self, metrics: Arc<crate::metrics::Metrics>) -> Self {
		self.metrics = Some(metrics);
		self
	}

	/// Deliver `event`, to the endpoint of the domain it names, if it names
	/// one (`MessageReceived`), else to the server-wide one. Fails open:
	/// transport/serialization errors are logged, never propagated.
	pub async fn notify(&self, event: &WebhookEvent) {
		self.notify_for(event.hosted_domain().as_deref(), event)
			.await;
	}

	/// Deliver `event` as an event of the hosted `domain`. A domain of a
	/// tenant with its own webhook posts to that one only, signed with that
	/// tenant's secret, and to nothing when the tenant's webhook is off: it
	/// never falls back to the server-wide webhook or to another tenant's.
	/// Any other domain, and `None`, posts to the server-wide webhook.
	pub async fn notify_for(&self, domain: Option<&str>, event: &WebhookEvent) {
		let Some(endpoint) = self.endpoint_for(domain) else {
			return;
		};
		let body = match serde_json::to_vec(event) {
			Ok(body) => body,
			Err(error) => {
				tracing::warn!(%error, "webhook payload serialization failed");
				return;
			}
		};
		match endpoint.request(body).send().await {
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

	/// The one endpoint an event of `domain` goes to, if any.
	fn endpoint_for(&self, domain: Option<&str>) -> Option<&Endpoint> {
		match domain.and_then(|domain| self.tenants.get(&domain.to_ascii_lowercase())) {
			Some(tenant) => tenant.as_deref(),
			None => self.default.as_ref(),
		}
	}

	/// Post the `test` event and report what the endpoint answered. Unlike
	/// [`Webhook::notify`] this surfaces failures and the HTTP status, and it
	/// does not touch the delivery metrics.
	pub async fn send_test(&self) -> Result<reqwest::StatusCode, WebhookError> {
		let event = WebhookEvent::Test {
			message: TEST_MESSAGE.into(),
		};
		let body = serde_json::to_vec(&event).expect("a test event always serializes");
		let endpoint = self.default.as_ref().ok_or(WebhookError::NoEndpoint)?;
		Ok(endpoint.request(body).send().await?.status())
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
