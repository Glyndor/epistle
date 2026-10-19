//! Management API configuration.

use serde::Deserialize;

/// Management API settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Api {
	/// argon2id PHC hash of the bearer token.
	pub token_hash: String,
	/// Account names allowed to authenticate to the admin panel. An account
	/// that authenticates but is not listed is a valid user, not an admin;
	/// empty (the default) means no account is a panel admin.
	#[serde(default)]
	pub admins: Vec<String>,
	/// Networks allowed to supply the client address through X-Forwarded-For.
	#[serde(default, deserialize_with = "trusted_proxies")]
	pub trusted_proxies: Vec<crate::cidr::Cidr>,
}

/// Deserialize trusted proxy networks once, rejecting malformed CIDR entries.
fn trusted_proxies<'de, D: serde::Deserializer<'de>>(
	deserializer: D,
) -> Result<Vec<crate::cidr::Cidr>, D::Error> {
	Vec::<String>::deserialize(deserializer)?
		.into_iter()
		.map(|spec| {
			if !spec.contains('/') {
				return Err(serde::de::Error::custom(
					"[api] trusted_proxies entries must be IPv4 or IPv6 CIDR networks",
				));
			}
			crate::cidr::Cidr::parse(&spec).ok_or_else(|| {
				serde::de::Error::custom(format!(
					"[api] trusted_proxies contains invalid CIDR: {spec}"
				))
			})
		})
		.collect()
}

#[cfg(test)]
#[path = "api_tests.rs"]
mod tests;
