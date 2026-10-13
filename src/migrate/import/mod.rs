//! Importing another server's configuration: what to create (the [`Plan`]
//! a source reader builds) and the writes that create it ([`apply`]).
//!
//! A plan is built without touching anything, so `--dry-run` shows it as
//! is. It never holds a password, and its keys are kept out of every
//! printed or serialised form.

pub(crate) mod apply;
pub(crate) mod keys;
#[cfg(test)]
pub(crate) mod test_keys;

use serde::Serialize;
use zeroize::Zeroizing;

pub(crate) use keys::Algorithm;

/// Everything a source configuration asks for.
#[derive(Debug, Default, Serialize)]
pub(crate) struct Plan {
	/// What was read, for the operator.
	pub(crate) source: String,
	/// Mail domains, ASCII (IDNA) and lowercase.
	pub(crate) domains: Vec<String>,
	/// Accounts to create.
	pub(crate) accounts: Vec<Account>,
	/// Multi-member aliases to create.
	pub(crate) aliases: Vec<Alias>,
	/// DKIM keys, each with the selector it is published under.
	pub(crate) keys: Vec<Key>,
	/// Things in the source that cannot be imported, and why.
	pub(crate) skipped: Vec<Note>,
	/// What has to be moved another way.
	pub(crate) manual: Vec<String>,
}

/// One account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Account {
	/// The login name.
	pub(crate) name: String,
	/// Its addresses.
	pub(crate) addresses: Vec<String>,
	/// Domains it receives otherwise unknown addresses for.
	pub(crate) catch_all: Vec<String>,
	/// The person's name, when the source has one.
	pub(crate) display_name: Option<String>,
}

/// One alias.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Alias {
	/// The alias address.
	pub(crate) address: String,
	/// Where it delivers.
	pub(crate) members: Vec<String>,
	/// Whether its membership stays private.
	pub(crate) hidden: bool,
}

/// One DKIM key. The key material is never serialised or printed.
#[derive(Serialize)]
pub(crate) struct Key {
	/// The signing domain.
	pub(crate) domain: String,
	/// The selector its public half is published under.
	pub(crate) selector: String,
	/// The algorithm.
	pub(crate) algorithm: Algorithm,
	/// PKCS#8 DER.
	#[serde(skip)]
	pub(crate) pkcs8: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for Key {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("Key")
			.field("domain", &self.domain)
			.field("selector", &self.selector)
			.field("algorithm", &self.algorithm)
			.finish_non_exhaustive()
	}
}

/// Something left out, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Note {
	/// What it is (`account bob`, `alias team@example.org`).
	pub(crate) item: String,
	/// Why it was left out.
	pub(crate) reason: String,
}

impl Plan {
	/// Record `item` as left out for `reason`.
	pub(crate) fn skip(&mut self, item: impl Into<String>, reason: impl Into<String>) {
		self.skipped.push(Note {
			item: item.into(),
			reason: reason.into(),
		});
	}

	/// Add `domain` once.
	pub(crate) fn add_domain(&mut self, domain: &str) {
		if !self.domains.iter().any(|known| known == domain) {
			self.domains.push(domain.to_string());
		}
	}
}

/// The lowercase ASCII form of a domain written in Unicode or ASCII, if it
/// is a valid DNS name.
pub(crate) fn domain(raw: &str) -> Option<String> {
	let ascii = idna::domain_to_ascii(raw.trim()).ok()?.to_ascii_lowercase();
	crate::config::validate_dns_name("domain", &ascii).ok()?;
	Some(ascii)
}

/// Whether `name` (already in its stored, lowercase form) is a name the
/// account store accepts; the reason when it is not.
pub(crate) fn account_name(name: &str) -> Result<(), String> {
	crate::directory_store::validate_name(name).map_err(|error| error.to_string())
}

/// An address with its domain in lowercase ASCII and its local part
/// lowercased, if it has both parts.
pub(crate) fn address(raw: &str) -> Option<String> {
	let (local, host) = raw.trim().rsplit_once('@')?;
	if local.is_empty() || local.chars().any(|c| c.is_control() || c.is_whitespace()) {
		return None;
	}
	Some(format!("{}@{}", local.to_lowercase(), domain(host)?))
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
