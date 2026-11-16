//! Management API configuration.

use serde::Deserialize;

/// Management API settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Api {
	/// Optional static bearer hash: SHA-256 or legacy argon2id PHC.
	/// Absent means only labelled API keys can pass bearer authentication.
	#[serde(default)]
	pub token_hash: Option<String>,
	/// Account names allowed to authenticate to the admin panel. An account
	/// that authenticates but is not listed is a valid user, not an admin;
	/// empty (the default) means no account is a panel admin.
	#[serde(default)]
	pub admins: Vec<String>,
	/// Networks allowed to supply the client address through X-Forwarded-For.
	#[serde(default, deserialize_with = "trusted_proxies")]
	pub trusted_proxies: Vec<crate::cidr::Cidr>,
	/// Limits on failed bearer sign-ins and on password checks; see
	/// [`crate::config::ApiLimiter`]. Absent keeps the built-in values.
	#[serde(default)]
	pub limiter: crate::config::ApiLimiter,
	/// Admin event streams (`GET /api/v1/events`) one key may hold open.
	/// Absent means 4.
	#[serde(default, deserialize_with = "streams_per_key")]
	pub event_streams_per_key: Option<usize>,
	/// Admin event streams the server holds open in all. Absent means 64.
	#[serde(default, deserialize_with = "streams_per_server")]
	pub event_streams_per_server: Option<usize>,
	/// Seconds an admin event stream stays open before the client has to
	/// reconnect. Absent means 3600.
	#[serde(default, deserialize_with = "stream_lifetime")]
	pub event_stream_max_secs: Option<u64>,
}

/// Read an optional whole number that must lie in `range`.
fn within<'de, D, T>(
	deserializer: D,
	key: &str,
	range: std::ops::RangeInclusive<T>,
) -> Result<Option<T>, D::Error>
where
	D: serde::Deserializer<'de>,
	T: Deserialize<'de> + PartialOrd + std::fmt::Display + Copy,
{
	let value = Option::<T>::deserialize(deserializer)?;
	match value {
		Some(value) if !range.contains(&value) => Err(serde::de::Error::custom(format!(
			"[api] {key} is {value}; it must be between {} and {}",
			range.start(),
			range.end()
		))),
		other => Ok(other),
	}
}

fn streams_per_key<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<usize>, D::Error> {
	within(d, "event_streams_per_key", 1..=1024)
}

fn streams_per_server<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<usize>, D::Error> {
	within(d, "event_streams_per_server", 1..=65536)
}

fn stream_lifetime<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<u64>, D::Error> {
	within(d, "event_stream_max_secs", 60..=86400)
}

/// Maximum number of CIDR networks `trusted_proxies` may list. Beyond this
/// the lookup in `effective_client_ip` is O(n) per parsed forwarded address,
/// so the cap exists to bound the cost of a misconfigured or hostile list.
pub(super) const MAX_TRUSTED_PROXIES: usize = 1024;

/// Deserialize trusted proxy networks once, rejecting malformed CIDR entries,
/// a universal `0` prefix (`0.0.0.0/0` or `::/0`), duplicates, and lists
/// above [`MAX_TRUSTED_PROXIES`].
fn trusted_proxies<'de, D: serde::Deserializer<'de>>(
	deserializer: D,
) -> Result<Vec<crate::cidr::Cidr>, D::Error> {
	let raw = Vec::<String>::deserialize(deserializer)?;
	if raw.len() > MAX_TRUSTED_PROXIES {
		return Err(serde::de::Error::custom(format!(
			"[api] trusted_proxies has {} entries, the maximum is {MAX_TRUSTED_PROXIES}",
			raw.len()
		)));
	}
	let mut out: Vec<crate::cidr::Cidr> = Vec::with_capacity(raw.len());
	let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
	for spec in raw {
		if !spec.contains('/') {
			// A bare address is a fair mistake and gets the prefix hint; a
			// value that is no address at all gets the general refusal.
			let message = if spec.parse::<std::net::IpAddr>().is_ok() {
				format!(
					"{:?} has no prefix length; an entry is an IPv4 or IPv6 network, for example \"10.0.0.0/8\" or \"2001:db8::/32\"",
					crate::util::address_reason::shorten(&spec)
				)
			} else {
				crate::cidr::Cidr::refusal(&spec)
			};
			return Err(serde::de::Error::custom(format!(
				"[api] trusted_proxies: {message}"
			)));
		}
		let cidr = crate::cidr::Cidr::parse(&spec).ok_or_else(|| {
			serde::de::Error::custom(format!(
				"[api] trusted_proxies: {}",
				crate::cidr::Cidr::refusal(&spec)
			))
		})?;
		if cidr.prefix() == 0 {
			return Err(serde::de::Error::custom(format!(
				"[api] trusted_proxies rejects {spec}: a /0 prefix trusts every address and \
				 lets a direct peer pick its own IP through X-Forwarded-For"
			)));
		}
		if seen.insert(cidr.to_string()) {
			out.push(cidr);
		}
	}
	Ok(out)
}

#[cfg(test)]
mod tests;
