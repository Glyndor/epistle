//! The checks a webhook section passes, the same for the server-wide
//! `[webhook]` and for a tenant's `[tenant.webhook]`: one destination policy
//! for every URL the server posts event payloads to.

use super::Webhook;
use crate::config::ConfigError;

impl Webhook {
	/// Check the section. `label` names it in the message (`[webhook]` or
	/// `[tenant.webhook]` of a tenant).
	///
	/// Event payloads carry message metadata, so TLS is required, except for a
	/// loopback endpoint, which never leaves the host. The host is compared
	/// after parsing: a name that only starts like `localhost` or `127.0.0.1`
	/// can point anywhere.
	pub(in crate::config) fn validate_as(&self, label: &str) -> Result<(), ConfigError> {
		let refused = || {
			ConfigError::Invalid(format!(
				"{label} url must be https (or a loopback http endpoint)"
			))
		};
		let url = url::Url::parse(&self.url).map_err(|_| refused())?;
		let loopback = match url.host() {
			Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
			Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
			Some(url::Host::Domain(name)) => name.eq_ignore_ascii_case("localhost"),
			None => false,
		};
		// A private destination needs the operator to say so: the webhook
		// client refuses those destinations, so a section that names one
		// without the option never delivers. The file still loads, because a
		// webhook is advisory and a configuration that worked before must not
		// stop the server from starting after an upgrade.
		let private = crate::webhook::destination::names_private(&self.url);
		if private && !self.allow_private_webhooks {
			tracing::warn!(
				"{label} url names a private address and no webhook will be delivered; set allow_private_webhooks = true to reach it"
			);
		}
		match url.scheme() {
			"https" => Ok(()),
			"http" if loopback => Ok(()),
			"http" if private && self.allow_private_webhooks => Ok(()),
			_ => Err(refused()),
		}
	}
}
