//! API keys made and revoked through the API, with the key that did it. The
//! secret of a key is never in the event, and neither is its hash.

use std::net::IpAddr;

/// Stable event identifiers on the API audit target.
#[derive(Debug, Clone, Copy)]
pub enum KeyEvent {
	/// Made a key.
	Created,
	/// Revoked a key.
	Revoked,
}

impl KeyEvent {
	fn as_str(self) -> &'static str {
		match self {
			Self::Created => "key.created",
			Self::Revoked => "key.revoked",
		}
	}
}

/// One event per durable change. `subject` is the label of the key that was
/// made or revoked and `by` the label of the key that did it (`None` for the
/// configured token). The scopes a new key holds are written, so a log shows
/// what a key was given.
pub fn log_key_change(
	event: KeyEvent,
	subject: &str,
	scopes: &[String],
	by: Option<&str>,
	client_ip: Option<IpAddr>,
) {
	let ip = client_ip.map_or_else(|| "unknown".to_string(), |ip| ip.to_string());
	tracing::info!(target: "epistle::api::audit", event = event.as_str(),
		subject = %subject, scopes = %scopes.join(","),
		key = by.unwrap_or("configured-token"), client_ip = %ip, "key change");
}
