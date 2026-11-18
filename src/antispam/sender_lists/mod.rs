//! Allow and deny lists of senders and recipients: the entries an operator
//! writes and the matcher that reads them.
//!
//! An entry is one of three shapes, matched without regard to case:
//!
//! - `user@example.com`: that address and no other.
//! - `example.com`: that domain only. Its subdomains are not covered.
//! - `*.example.com`: every subdomain of `example.com` at any depth, and not
//!   `example.com` itself. `badexample.com` and `example.com.example.net` are
//!   not subdomains of `example.com` and never match.
//!
//! The null reverse path (`<>`) names nobody and never matches an entry, so
//! a list cannot refuse or favour bounces.

use std::collections::HashSet;

/// Longest entry accepted, the longest domain name plus a local part.
pub const MAX_ENTRY_LEN: usize = 320;
/// Most entries in one list.
pub const MAX_ENTRIES: usize = 4096;

/// What an entry names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Entry {
	/// One address, lower case.
	Address(String),
	/// One domain, lower case, no trailing dot.
	Domain(String),
	/// Every subdomain of this domain, lower case.
	Subdomains(String),
}

/// Why a list entry was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryError(pub String);

impl std::fmt::Display for EntryError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str(&self.0)
	}
}

/// Whether `domain` is a plausible DNS name: dot separated labels of ASCII
/// letters, digits and `-`, none empty, none longer than 63 bytes, none
/// starting or ending with `-`, and at least two labels.
fn valid_domain(domain: &str) -> bool {
	domain.len() <= 253
		&& domain.split('.').count() >= 2
		&& domain.split('.').all(|label| {
			!label.is_empty()
				&& label.len() <= 63
				&& !label.starts_with('-')
				&& !label.ends_with('-')
				&& label
					.bytes()
					.all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
		})
}

/// `domain` the way the rest of the server keys it: trailing dot dropped,
/// internationalised names as their lower case A-label (see
/// [`crate::domain::normalize`]). `None` when it is not a usable name.
fn clean_domain(domain: &str) -> Option<String> {
	crate::domain::normalize(domain.trim().trim_end_matches('.')).ok()
}

/// `address` as the lists compare it: the lower case local part without
/// quotes, and the domain as [`clean_domain`] gives it. A surrounding `<>`,
/// spaces and a trailing dot on the domain do not change the answer.
fn identify(address: &str) -> Option<(String, String)> {
	let address = address.trim().trim_start_matches('<').trim_end_matches('>');
	let (local, domain) = address.rsplit_once('@')?;
	let local = local.trim().trim_matches('"').to_lowercase();
	Some((local, clean_domain(domain)?))
}

impl Entry {
	/// `text` with its domain part in the form the lists compare.
	fn normalised(text: &str) -> String {
		let text = text.trim().to_lowercase();
		let (prefix, rest) = match text.strip_prefix("*.") {
			Some(rest) => ("*.", rest),
			None => ("", text.as_str()),
		};
		let (local, domain) = match rest.rsplit_once('@') {
			Some((local, domain)) => (format!("{local}@"), domain),
			None => (String::new(), rest),
		};
		match clean_domain(domain) {
			Some(domain) => format!("{prefix}{local}{domain}"),
			None => text,
		}
	}

	/// Parse one entry as the configuration spells it. Domains may be
	/// written as Unicode and are kept as their A-label.
	pub fn parse(text: &str) -> Result<Self, EntryError> {
		let text = Self::normalised(text);
		let bad = |why: &str| EntryError(format!("{text:?}: {why}"));
		if text.is_empty() || text.len() > MAX_ENTRY_LEN {
			return Err(bad("must be 1 to 320 characters"));
		}
		if let Some(rest) = text.strip_prefix("*.") {
			return if valid_domain(rest) {
				Ok(Self::Subdomains(rest.to_string()))
			} else {
				Err(bad("`*.` must be followed by a domain name"))
			};
		}
		if text.contains('*') {
			return Err(bad("`*` is only allowed as a leading `*.`"));
		}
		match text.split_once('@') {
			Some((local, domain)) => {
				let local_ok = !local.is_empty()
					&& !local.contains(['@', ' ', '<', '>', ','])
					&& local.is_ascii();
				if local_ok && valid_domain(domain) {
					Ok(Self::Address(text))
				} else {
					Err(bad("not an address"))
				}
			}
			None if valid_domain(&text) => Ok(Self::Domain(text)),
			None => Err(bad("not an address or a domain name")),
		}
	}
}

/// A compiled list.
#[derive(Clone, Debug, Default)]
pub struct Matcher {
	addresses: HashSet<String>,
	domains: HashSet<String>,
	/// `.example.com`, with the leading dot, so a suffix test cannot match
	/// `badexample.com`.
	suffixes: Vec<String>,
}

impl Matcher {
	/// Compile `entries`, which the configuration has already validated.
	/// An entry that does not parse is ignored.
	pub fn new(entries: &[String]) -> Self {
		let mut matcher = Self::default();
		for entry in entries.iter().filter_map(|text| Entry::parse(text).ok()) {
			match entry {
				Entry::Address(address) => {
					matcher.addresses.insert(address);
				}
				Entry::Domain(domain) => {
					matcher.domains.insert(domain);
				}
				Entry::Subdomains(domain) => matcher.suffixes.push(format!(".{domain}")),
			}
		}
		matcher
	}

	/// Whether the list has no entry.
	pub fn is_empty(&self) -> bool {
		self.addresses.is_empty() && self.domains.is_empty() && self.suffixes.is_empty()
	}

	/// Whether `address` is named by an entry. An empty address, the null
	/// reverse path, and one with no domain never match.
	pub fn matches(&self, address: &str) -> bool {
		if self.is_empty() {
			return false;
		}
		let Some((local, domain)) = identify(address) else {
			return false;
		};
		if self.addresses.contains(&format!("{local}@{domain}")) {
			return true;
		}
		self.domains.contains(&domain)
			|| self
				.suffixes
				.iter()
				.any(|suffix| domain.ends_with(suffix.as_str()))
	}
}

#[cfg(test)]
mod tests;
