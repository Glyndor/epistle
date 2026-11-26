//! Ban and allow-list changes made through the API, with the key that made
//! them and no bearer in the event.

use std::net::IpAddr;

/// Stable event identifiers on the API audit target.
#[derive(Debug, Clone, Copy)]
pub enum BanEvent {
	/// Banned an address or a network.
	Banned,
	/// Lifted a ban.
	Unbanned,
	/// Added a block to the allow list.
	Allowed,
	/// Took a block off the allow list.
	Disallowed,
}

impl BanEvent {
	fn as_str(self) -> &'static str {
		match self {
			Self::Banned => "ban.added",
			Self::Unbanned => "ban.removed",
			Self::Allowed => "ban.allow_added",
			Self::Disallowed => "ban.allow_removed",
		}
	}
}

/// What the log says of a subject: an address or a network in the clear, an
/// account as the pseudonym the logs use for names.
fn shown(subject: &str) -> String {
	if let Some(login) = subject.strip_prefix("account:") {
		return format!("account:{}", crate::log_id::account(login));
	}
	if let Some(rest) = subject.strip_prefix("pair:") {
		return match rest.rsplit_once('|') {
			Some((login, client)) => format!("pair:{}|{client}", crate::log_id::account(login)),
			None => "pair:".to_string(),
		};
	}
	subject.to_string()
}

/// One event per durable change. A refused request and one that changed
/// nothing emit none. `key` is the label of the API key (never the key);
/// `None` for the configured token.
pub fn log_ban_change(
	event: BanEvent,
	subject: &str,
	key: Option<&str>,
	client_ip: Option<IpAddr>,
) {
	let ip = client_ip.map_or_else(|| "unknown".to_string(), |ip| ip.to_string());
	tracing::info!(target: "epistle::api::audit", event = event.as_str(),
		subject = %shown(subject), key = key.unwrap_or("configured-token"),
		client_ip = %ip, "ban change");
}
