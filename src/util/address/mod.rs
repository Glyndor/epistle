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
/// still sees (and reports) exactly why the value is invalid. A domain of one
/// label (`localhost`) is one of those: it comes back as `localhost`. A header
/// is data and the server must not rewrite it, so the normalizer keeps it;
/// the gate is [`crate::domain::normalize`], and every surface that creates
/// an address or a domain goes through it.
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

/// The local part and the domain of a mailbox that can go into a message
/// header as it is: printable ASCII, without the characters that would end
/// the header line or start another address.
///
/// This is the gate for every address the server writes into a header of a
/// message it signs — the `To:` of a report taken from a `rua=` a stranger
/// published, the `From:` of an aggregate report an operator configured — so
/// a value that passes can be written into the header without escaping it.
/// A value that does not pass is refused rather than escaped: the caller
/// decides what to do with it.
///
/// The rule is deliberately narrow. A quoted local part, an address literal
/// and a display name are all valid RFC 5322 mailboxes that this refuses.
pub fn plain_mailbox(mailbox: &str) -> Option<(&str, &str)> {
	let (local, domain) = mailbox.split_once('@')?;
	let plain = |part: &str| {
		!part.is_empty()
			&& part
				.bytes()
				.all(|byte| byte.is_ascii_graphic() && !b"@<>,;:\\\"()[]".contains(&byte))
	};
	(plain(local) && plain(domain) && mailbox.len() <= 254).then_some((local, domain))
}

#[cfg(test)]
mod tests;
