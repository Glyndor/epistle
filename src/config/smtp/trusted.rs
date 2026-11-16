//! Reading `[smtp] trusted_networks`: the entries are parsed once, at load.

use serde::Deserialize;

/// The most networks the list may name. Every inbound message from an
/// unknown peer walks the list, so the cap bounds that cost.
pub(super) const MAX_TRUSTED_NETWORKS: usize = 256;
/// The shortest IPv4 prefix an entry may have: a /8 is sixteen million
/// addresses, already more than any relay set, and a typo such as
/// `10.0.0.0/1` must not turn the screens off for half the internet.
pub(super) const MIN_V4_PREFIX: u8 = 8;
/// The shortest IPv6 prefix an entry may have, for the same reason.
pub(super) const MIN_V6_PREFIX: u8 = 32;

/// Parse the list, refusing a malformed entry, one that is too wide, a
/// duplicate and a list over [`MAX_TRUSTED_NETWORKS`]. Every message names
/// the key.
pub(super) fn trusted_networks<'de, D: serde::Deserializer<'de>>(
	deserializer: D,
) -> Result<Vec<crate::cidr::Cidr>, D::Error> {
	let raw = Vec::<String>::deserialize(deserializer)?;
	if raw.len() > MAX_TRUSTED_NETWORKS {
		return Err(serde::de::Error::custom(format!(
			"[smtp] trusted_networks has {} entries, the maximum is {MAX_TRUSTED_NETWORKS}",
			raw.len()
		)));
	}
	let mut out: Vec<crate::cidr::Cidr> = Vec::with_capacity(raw.len());
	for spec in raw {
		let cidr = crate::cidr::Cidr::parse(&spec).ok_or_else(|| {
			serde::de::Error::custom(format!(
				"[smtp] trusted_networks: {}",
				crate::cidr::Cidr::refusal(&spec)
			))
		})?;
		let floor = match cidr.network() {
			std::net::IpAddr::V4(_) => MIN_V4_PREFIX,
			std::net::IpAddr::V6(_) => MIN_V6_PREFIX,
		};
		if cidr.prefix() < floor {
			return Err(serde::de::Error::custom(format!(
				"[smtp] trusted_networks: {cidr} is too wide, the shortest prefix allowed is /{floor}"
			)));
		}
		if out.contains(&cidr) {
			return Err(serde::de::Error::custom(format!(
				"[smtp] trusted_networks lists {cidr} more than once"
			)));
		}
		out.push(cidr);
	}
	Ok(out)
}
