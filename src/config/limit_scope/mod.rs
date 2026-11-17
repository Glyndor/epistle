//! The `[limits]` table and the `[[limit_scope]]` entries: caps on what an
//! account, a domain or a message may hold, at the server, for one tenant,
//! one domain or one account.
//!
//! `[limits]` is the server scope. A `[[limit_scope]]` entry names exactly
//! one of `tenant`, `domain` or `account`, and sets the same keys. Every key
//! is absent (the wider scope's value stands), a number, or `"unlimited"`.
//! A narrower scope may only tighten what a wider one allows: the load
//! refuses a number above it and refuses `"unlimited"` under it. How the
//! scopes resolve is in [`crate::limits`], and the unit of each key is in
//! `docs/configuration.md`.

use serde::de::{self, Deserializer, Visitor};
use serde::{Deserialize, Serialize};

mod validate;

/// One cap: a number of things, or no cap at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Limit {
	/// No cap from this scope.
	Unlimited,
	/// At most this many; `0` allows none.
	Max(u64),
}

impl Serialize for Limit {
	fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
		match self {
			Self::Unlimited => serializer.serialize_str("unlimited"),
			Self::Max(value) => serializer.serialize_u64(*value),
		}
	}
}

impl<'de> Deserialize<'de> for Limit {
	fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
		struct Reader;
		impl Visitor<'_> for Reader {
			type Value = Limit;

			fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
				f.write_str("a whole number, or \"unlimited\"")
			}

			fn visit_u64<E: de::Error>(self, value: u64) -> Result<Limit, E> {
				// The TOML integer is signed: a value past it cannot be the
				// operator's.
				if value > i64::MAX as u64 {
					return Err(E::custom("the number is too large"));
				}
				Ok(Limit::Max(value))
			}

			fn visit_i64<E: de::Error>(self, value: i64) -> Result<Limit, E> {
				u64::try_from(value)
					.map(Limit::Max)
					.map_err(|_| E::custom("a limit cannot be negative"))
			}

			fn visit_str<E: de::Error>(self, value: &str) -> Result<Limit, E> {
				if value.eq_ignore_ascii_case("unlimited") {
					Ok(Limit::Unlimited)
				} else {
					Err(E::custom(format!(
						"{value:?} is not a limit: write a whole number, or \"unlimited\""
					)))
				}
			}
		}
		deserializer.deserialize_any(Reader)
	}
}

/// What happens to the oldest session when an account is at its cap and one
/// more is opened.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionsWhenFull {
	/// The session that expires first is ended to make room.
	#[default]
	EndOldest,
	/// The new session is refused until one ends or is revoked.
	Refuse,
}

/// The caps of one scope. A field left out keeps the wider scope's value.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Caps {
	/// Largest message, in bytes, an account of the scope may send or
	/// receive. Never above the server's `max_message_size`, never below
	/// 64 KiB.
	pub max_message_size: Option<Limit>,
	/// Addresses one account may hold.
	pub max_addresses_per_account: Option<Limit>,
	/// Aliases (lists included) one domain may hold.
	pub max_aliases_per_domain: Option<Limit>,
	/// Mailing lists (aliases with a `list_id`) one domain may hold.
	pub max_lists_per_domain: Option<Limit>,
	/// Members one alias or list may have.
	pub max_members_per_list: Option<Limit>,
	/// API keys bound to one account.
	pub max_api_keys_per_account: Option<Limit>,
	/// App passwords one account may hold.
	pub max_app_passwords_per_account: Option<Limit>,
	/// OAuth refresh-token families one account may hold at once. The
	/// server default is 50.
	pub max_sessions_per_account: Option<Limit>,
	/// Whether an account at its session cap ends its oldest session or
	/// refuses the new one. The most specific scope that sets it wins.
	pub sessions_when_full: Option<SessionsWhenFull>,
}

impl Caps {
	/// Whether the scope sets nothing.
	pub fn is_empty(&self) -> bool {
		*self == Self::default()
	}
}

/// One `[[limit_scope]]` entry: the caps of one tenant, domain or account.
#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(try_from = "toml::Table")]
pub struct LimitScope {
	/// The `name` of a `[[tenant]]`: every domain of the tenant.
	pub tenant: Option<String>,
	/// A hosted domain, which must also be in `domains`.
	pub domain: Option<String>,
	/// An account name, from any source. Not checked against a list: an
	/// unknown name has no effect.
	pub account: Option<String>,
	/// The caps of the scope.
	pub caps: Caps,
}

impl TryFrom<toml::Table> for LimitScope {
	type Error = String;

	/// The three selectors are read here and the rest is the caps, read with
	/// `deny_unknown_fields`, so a misspelled key is an error and not a
	/// limit that silently does nothing.
	fn try_from(mut table: toml::Table) -> Result<Self, String> {
		let mut selector = |key: &str| -> Result<Option<String>, String> {
			match table.remove(key) {
				None => Ok(None),
				Some(toml::Value::String(name)) => Ok(Some(name)),
				Some(_) => Err(format!("[[limit_scope]] {key} must be a string")),
			}
		};
		let tenant = selector("tenant")?;
		let domain = selector("domain")?;
		let account = selector("account")?;
		let caps = Caps::deserialize(toml::Value::Table(table))
			.map_err(|error| format!("[[limit_scope]]: {}", error.message()))?;
		Ok(Self {
			tenant,
			domain,
			account,
			caps,
		})
	}
}

#[cfg(test)]
mod tests;
