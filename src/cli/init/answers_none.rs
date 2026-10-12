//! `"none"` as the value of `public_ipv4` / `public_ipv6` in an answers
//! file: the operator says there is no public address of that family.
//! A key left out means "propose one from the host's interfaces"; a key
//! set to `"none"` means "no address" and detection never overrides it,
//! the same answer the interactive `none` gives. Both deserialise to
//! `None`, so the difference is read separately from the raw file.

use std::net::{Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Deserializer};

/// The families an answers file explicitly sets to `"none"`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct Declined {
	pub(super) v4: bool,
	pub(super) v6: bool,
}

/// Which families `raw` (an answers file that already parsed as
/// `Answers`) sets to `"none"`.
pub(super) fn declined(raw: &str) -> Declined {
	let Ok(table) = raw.parse::<toml::Table>() else {
		return Declined::default();
	};
	let says_none = |key: &str| {
		table
			.get(key)
			.and_then(toml::Value::as_str)
			.is_some_and(is_none)
	};
	Declined {
		v4: says_none("public_ipv4"),
		v6: says_none("public_ipv6"),
	}
}

/// The one spelling of "no address", case aside.
fn is_none(text: &str) -> bool {
	text.eq_ignore_ascii_case("none")
}

/// `public_ipv4`: an IPv4 address, or `"none"` for no address.
pub(super) fn ipv4<'de, D: Deserializer<'de>>(
	deserializer: D,
) -> Result<Option<Ipv4Addr>, D::Error> {
	address(deserializer)
}

/// `public_ipv6`: an IPv6 address, or `"none"` for no address.
pub(super) fn ipv6<'de, D: Deserializer<'de>>(
	deserializer: D,
) -> Result<Option<Ipv6Addr>, D::Error> {
	address(deserializer)
}

/// An address or `"none"`. Anything else is rejected with the parser's
/// own message, the one a bad address got before `"none"` existed.
fn address<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
	D: Deserializer<'de>,
	T: std::str::FromStr,
	T::Err: std::fmt::Display,
{
	let text = String::deserialize(deserializer)?;
	if is_none(&text) {
		return Ok(None);
	}
	text.parse().map(Some).map_err(serde::de::Error::custom)
}

#[cfg(test)]
#[path = "answers_none_tests.rs"]
mod tests;
