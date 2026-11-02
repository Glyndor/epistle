//! Which webhook an event goes to: the one of the tenant that owns the
//! hosted domain the event belongs to, or the server-wide one.

use std::collections::HashMap;
use std::sync::Arc;

use super::{Endpoint, Webhook, WebhookEvent};
use crate::config::Config;

/// The poster for a configuration: the server-wide `[webhook]` when it is on,
/// and the `[tenant.webhook]` of every tenant that has one. `None` when no
/// endpoint can be used. A destination the webhook client refuses leaves that
/// webhook without a poster and says so, and the others keep theirs: the
/// webhook is advisory, and a configuration that loaded before the
/// destination policy must still start the server.
pub fn from_config(config: &Config) -> Option<Webhook> {
	let default = config.active_webhook().and_then(|section| {
		Endpoint::from_section(section)
			.map_err(|error| {
				tracing::warn!(%error, "the webhook cannot be used and no event will be sent");
			})
			.ok()
	});
	let mut tenants: HashMap<String, Option<Arc<Endpoint>>> = HashMap::new();
	for tenant in &config.tenants {
		let Some(section) = &tenant.webhook else {
			continue;
		};
		// A tenant whose webhook is off or cannot be used keeps its domains
		// out of the server-wide webhook as well: the entry exists, empty.
		let endpoint = section
			.enabled
			.then(|| Endpoint::from_section(section))
			.and_then(|built| {
				built
					.map_err(|error| {
						tracing::warn!(
							%error,
							tenant = tenant.name.as_deref().unwrap_or("<unnamed tenant>"),
							"the tenant webhook cannot be used and none of its events will be sent"
						);
					})
					.ok()
			})
			.map(Arc::new);
		for domain in &tenant.domains {
			let domain = domain.to_ascii_lowercase();
			// A domain alias delivers as its target, so its events are the
			// target's tenant's.
			for (alias, target) in &config.domain_aliases {
				if target.eq_ignore_ascii_case(&domain) {
					tenants.insert(alias.to_ascii_lowercase(), endpoint.clone());
				}
			}
			tenants.insert(domain, endpoint.clone());
		}
	}
	let any_tenant = tenants.values().any(Option::is_some);
	(default.is_some() || any_tenant).then_some(Webhook {
		default,
		tenants,
		metrics: None,
	})
}

/// The one hosted domain a set of addresses sits in, lowercase; `None` when
/// they are none, or sit in more than one. This is for addresses the server
/// itself resolved (the account that authenticated, the local recipients of
/// a delivery), never for an envelope sender, which its sender writes.
pub fn single_domain<'a>(addresses: impl IntoIterator<Item = &'a str>) -> Option<String> {
	let mut found: Option<String> = None;
	for address in addresses {
		let domain = address_domain(address)?;
		match &found {
			Some(known) if *known != domain => return None,
			_ => found = Some(domain),
		}
	}
	found
}

/// The owner of what `account` submits: the domain all its addresses sit in.
/// An account with addresses in several domains has no single owner, and its
/// events use the server-wide webhook rather than a guess.
pub fn account_owner(
	directory: &crate::smtp::directory::Directory,
	account: &str,
) -> Option<String> {
	let addresses = directory.addresses_for(account);
	single_domain(addresses.iter().map(String::as_str))
}

fn address_domain(address: &str) -> Option<String> {
	let (_, domain) = address.rsplit_once('@')?;
	(!domain.is_empty()).then(|| domain.to_ascii_lowercase())
}

impl WebhookEvent {
	/// The hosted domain this event is about, when the event itself says:
	/// the recipient's of a received message. Everything else (a metric
	/// alert, a key rotation, a warm-up report, the test event) belongs to
	/// the server, and the delivery events are routed by the sender's domain
	/// that the code posting them knows, through [`Webhook::notify_for`].
	pub fn hosted_domain(&self) -> Option<String> {
		match self {
			WebhookEvent::MessageReceived { account, .. } => address_domain(account),
			_ => None,
		}
	}
}
