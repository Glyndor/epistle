//! Changes to a queued message's schedule made through the API, with the key
//! that made them and no bearer in the event.

use std::net::IpAddr;

use uuid::Uuid;

/// Stable event identifiers on the API audit target.
#[derive(Debug, Clone, Copy)]
pub enum QueueEvent {
	/// Made the next attempt happen now.
	Retried,
	/// Put an entry on hold.
	Held,
	/// Released a held entry.
	Released,
}

impl QueueEvent {
	fn as_str(self) -> &'static str {
		match self {
			Self::Retried => "queue.retried",
			Self::Held => "queue.held",
			Self::Released => "queue.released",
		}
	}
}

/// One event per change that altered the entry. A refusal and a request that
/// found the entry as it was asked to leave it write none. `key` is the label
/// of the API key (never the key); `None` for the configured token.
pub fn log_queue_change(event: QueueEvent, id: Uuid, key: Option<&str>, client_ip: Option<IpAddr>) {
	let ip = client_ip.map_or_else(|| "unknown".to_string(), |ip| ip.to_string());
	tracing::info!(target: "epistle::api::audit", event = event.as_str(),
		id = %id, key = key.unwrap_or("configured-token"), client_ip = %ip, "queue change");
}
