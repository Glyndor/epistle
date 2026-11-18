//! Hosted-domain changes, with no key material or bearer in the event.

/// Stable event identifiers on the API audit target.
#[derive(Debug, Clone, Copy)]
pub enum DomainEvent {
	/// Hosted a domain.
	Added,
	/// Stopped hosting a domain.
	Removed,
	/// Switched a domain off.
	Disabled,
	/// Switched a domain on.
	Enabled,
	/// Changed its role or limits atomically.
	Updated,
	/// Declared an alias.
	AliasAdded,
	/// Dropped an alias.
	AliasRemoved,
}

impl DomainEvent {
	fn as_str(self) -> &'static str {
		match self {
			Self::Added => "domain.added",
			Self::Removed => "domain.removed",
			Self::Disabled => "domain.disabled",
			Self::Enabled => "domain.enabled",
			Self::Updated => "domain.updated",
			Self::AliasAdded => "domain.alias_added",
			Self::AliasRemoved => "domain.alias_removed",
		}
	}
}

/// One event per durable change. No-op and refused writes emit none.
pub fn log_domain_change(event: DomainEvent, domain: &str, client_ip: Option<std::net::IpAddr>) {
	let ip = client_ip.map_or_else(|| "unknown".to_string(), |ip| ip.to_string());
	tracing::info!(target: "epistle::api::audit", event = event.as_str(),
		domain = %domain, client_ip = %ip, "domain change");
}
