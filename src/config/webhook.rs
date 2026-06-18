//! Outbound webhook configuration: deliver event notifications to an HTTP
//! endpoint, optionally signed with an HMAC-SHA256 secret.

use serde::Deserialize;

/// Where and how to POST event notifications. Present enables webhooks.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Webhook {
	/// The HTTPS endpoint that receives event payloads.
	pub url: String,
	/// Optional shared secret; when set, each request carries an
	/// `X-Webhook-Signature: sha256=<hex>` HMAC of the body.
	#[serde(default)]
	pub secret: Option<String>,
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn parses_webhook_section() {
		let webhook: Webhook = toml::from_str(
			r#"
url = "https://hooks.example/mail"
secret = "s3cret"
"#,
		)
		.expect("parse webhook");
		assert_eq!(webhook.url, "https://hooks.example/mail");
		assert_eq!(webhook.secret.as_deref(), Some("s3cret"));
	}

	#[test]
	fn secret_is_optional_and_unknown_keys_rejected() {
		let webhook: Webhook =
			toml::from_str(r#"url = "https://hooks.example/mail""#).expect("parse");
		assert!(webhook.secret.is_none());
		assert!(toml::from_str::<Webhook>(r#"url = "x""#).is_ok());
		assert!(toml::from_str::<Webhook>(r#"nope = "x""#).is_err());
	}
}
