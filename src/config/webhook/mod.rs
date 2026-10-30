//! Outbound webhook configuration: deliver event notifications to an HTTP
//! endpoint, optionally signed with an HMAC-SHA256 secret.

use serde::Deserialize;

/// Where and how to POST event notifications. Present enables webhooks.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Webhook {
	/// The HTTPS endpoint that receives event payloads.
	pub url: String,
	/// Optional shared secret; when set, each request carries an
	/// `X-Webhook-Signature: sha256=<hex>` HMAC of the body.
	#[serde(default)]
	pub secret: Option<String>,
	/// With `false` the section stays in the file but no event is posted.
	/// `epistle webhook disable|enable` flips it.
	#[serde(default = "default_enabled")]
	pub enabled: bool,
	/// Whether the endpoint may be a private destination: a loopback
	/// address, a private network of the site, or the link-local address
	/// where the cloud metadata lives. Off by default: the webhook client
	/// refuses those destinations, and a webhook that names one without
	/// this option would never deliver anything.
	#[serde(default)]
	pub allow_private_webhooks: bool,
}

const fn default_enabled() -> bool {
	true
}

impl std::fmt::Debug for Webhook {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("Webhook")
			.field("url", &self.url)
			.field("secret", &self.secret.as_ref().map(|_| "***"))
			.field("enabled", &self.enabled)
			.field("allow_private_webhooks", &self.allow_private_webhooks)
			.finish()
	}
}

#[cfg(test)]
mod tests;
