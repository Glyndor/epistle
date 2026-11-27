//! Changes to an account made through the API, with the key that made them.
//! The account is written as the pseudonym the logs use, and no secret is in
//! an event.
//!
//! The suspension events are the ones the management route that suspends and
//! resumes an account writes: the same names, the same fields and the same
//! rule about a request that found the account already in the state asked
//! for.

use std::net::IpAddr;

/// Stable event identifiers on the API audit target.
#[derive(Debug, Clone, Copy)]
pub enum SuspensionEvent {
	/// Suspended an account: it stops authenticating, its mail stays.
	Disabled,
	/// Resumed an account.
	Enabled,
}

impl SuspensionEvent {
	fn as_str(self) -> &'static str {
		match self {
			Self::Disabled => "account.disabled",
			Self::Enabled => "account.enabled",
		}
	}
}

/// One event per durable change; a request that found the account already in
/// the state asked for writes none. `key` is the label of the API key (never
/// the key); `None` for the configured token.
pub fn log_suspension_change(
	event: SuspensionEvent,
	account: &str,
	key: Option<&str>,
	client_ip: Option<IpAddr>,
) {
	let ip = client_ip.map_or_else(|| "unknown".to_string(), |ip| ip.to_string());
	tracing::info!(target: "epistle::api::audit", event = event.as_str(),
		account = %crate::log_id::account(account),
		key = key.unwrap_or("configured-token"), client_ip = %ip, "account change");
}
