//! Address-alias changes made through the API, with the key that made them
//! and no bearer in the event.

use std::net::IpAddr;

/// Stable event identifiers on the API audit target.
#[derive(Debug, Clone, Copy)]
pub enum AliasEvent {
	/// Made an alias.
	Added,
	/// Removed an alias.
	Removed,
}

impl AliasEvent {
	fn as_str(self) -> &'static str {
		match self {
			Self::Added => "alias.added",
			Self::Removed => "alias.removed",
		}
	}
}

/// One event per durable change. A dry run, a no-op and a refused write emit
/// none. `key` is the label of the API key (never the key); `None` for the
/// configured token. The alias is written as the pseudonym the logs use for
/// names, next to its domain in the clear.
pub fn log_alias_change(
	event: AliasEvent,
	alias: &str,
	key: Option<&str>,
	client_ip: Option<IpAddr>,
) {
	let ip = client_ip.map_or_else(|| "unknown".to_string(), |ip| ip.to_string());
	let domain = alias.rsplit_once('@').map_or("", |(_, domain)| domain);
	tracing::info!(target: "epistle::api::audit", event = event.as_str(),
		alias = %crate::log_id::account(alias), domain = %domain,
		key = key.unwrap_or("configured-token"), client_ip = %ip, "alias change");
}
