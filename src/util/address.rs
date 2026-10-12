//! The stored form of a mail address or a mail domain.
//!
//! Every address and domain epistle keeps (account addresses, alias
//! addresses, members and senders, masked addresses, forward targets,
//! catch-all and configured domains, domain aliases, suppression entries) is
//! stored in the form these functions return, whatever case the operator or
//! the API client typed. Lookups go through the same functions, so the
//! spelling of a recipient never decides where its mail lands.
//!
//! Only identifiers are normalized: message headers and bodies are never
//! rewritten. A person's name is not an address and never passes through
//! here.

/// The stored form of a mail address.
///
/// Trims surrounding whitespace, turns the domain into the lowercase ASCII
/// A-label [`crate::domain::normalize`] produces, and lowercases the local
/// part. An ASCII local part is lowercased with ASCII rules; a non-ASCII one
/// (RFC 6531) with Unicode `to_lowercase`, so `Ärger@example.org` and
/// `ärger@example.org` are the same mailbox. RFC 5321 allows a server to
/// treat local parts as case sensitive; epistle deliberately never does.
///
/// This never validates: a domain [`crate::domain::normalize`] refuses is
/// only lowercased, and input without `@` is lowercased whole, so the caller
/// still sees (and reports) exactly why the value is invalid.
pub fn normalize(raw: &str) -> String {
	let raw = raw.trim();
	match raw.rsplit_once('@') {
		Some((local, domain)) => format!("{}@{}", local.to_lowercase(), normalize_domain(domain)),
		None => raw.to_lowercase(),
	}
}

/// The stored form of a mail domain: trimmed, then the lowercase A-label from
/// [`crate::domain::normalize`], or plain lowercase when that refuses it.
pub fn normalize_domain(raw: &str) -> String {
	let raw = raw.trim();
	crate::domain::normalize(raw).unwrap_or_else(|_| raw.to_lowercase())
}

#[cfg(test)]
#[path = "address_tests.rs"]
mod tests;
