//! Changes to an account made through the API, with the key that made them.
//! The account is written as the pseudonym the logs use, and no secret is in
//! an event.
//!
//! The suspension events are the ones the management route that suspends and
//! resumes an account writes: the same names, the same fields and the same
//! rule about a request that found the account already in the state asked
//! for. The quota events are written once for every write of a quota, and the
//! address events once for every address written or taken off, next to the
//! domain in the clear.

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

/// One privileged change, with the key that made it. `key` is the label of
/// the API key (never the key); `None` for the configured token, which is
/// reported as `configured-token` so the field is never absent.
pub fn log_privilege_change_by_key(
	event: super::AuditEvent,
	account: &str,
	key: Option<&str>,
	client_ip: Option<IpAddr>,
) {
	let ip = client_ip.map_or_else(|| "unknown".to_string(), |ip| ip.to_string());
	tracing::info!(target: "epistle::api::audit", event = event.as_str(),
		account = %crate::log_id::account(account),
		key = key.unwrap_or("configured-token"), client_ip = %ip, "privilege change");
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

/// Stable event identifiers on the API audit target.
#[derive(Debug, Clone, Copy)]
pub enum QuotaEvent {
	/// Set the storage quota of an account.
	Set,
	/// Put an account back on the server default.
	Cleared,
}

impl QuotaEvent {
	fn as_str(self) -> &'static str {
		match self {
			Self::Set => "account.quota_set",
			Self::Cleared => "account.quota_cleared",
		}
	}
}

/// One event per write of a quota, with the quota it left; `0` stands for
/// none, the server default.
pub fn log_quota_change(
	event: QuotaEvent,
	account: &str,
	quota_bytes: Option<u64>,
	key: Option<&str>,
	client_ip: Option<IpAddr>,
) {
	let ip = client_ip.map_or_else(|| "unknown".to_string(), |ip| ip.to_string());
	tracing::info!(target: "epistle::api::audit", event = event.as_str(),
		account = %crate::log_id::account(account), quota_bytes = quota_bytes.unwrap_or(0),
		key = key.unwrap_or("configured-token"), client_ip = %ip, "account change");
}

/// Stable event identifiers on the API audit target.
#[derive(Debug, Clone, Copy)]
pub enum AddressEvent {
	/// Gave an account an address.
	Added,
	/// Took an address off an account.
	Removed,
}

impl AddressEvent {
	fn as_str(self) -> &'static str {
		match self {
			Self::Added => "account.address_added",
			Self::Removed => "account.address_removed",
		}
	}
}

/// One event per durable change; a refused write emits none. The address is
/// written as its pseudonym, and its domain in the clear.
pub fn log_address_change(
	event: AddressEvent,
	account: &str,
	address: &str,
	key: Option<&str>,
	client_ip: Option<IpAddr>,
) {
	let ip = client_ip.map_or_else(|| "unknown".to_string(), |ip| ip.to_string());
	let domain = address.rsplit_once('@').map_or("", |(_, domain)| domain);
	tracing::info!(target: "epistle::api::audit", event = event.as_str(),
		account = %crate::log_id::account(account),
		address = %crate::log_id::account(address), domain = %domain,
		key = key.unwrap_or("configured-token"), client_ip = %ip, "account change");
}
