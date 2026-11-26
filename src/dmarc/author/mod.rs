//! The RFC5322.From field of a message, read once and the same way for
//! every consumer: the DMARC Author Domain (RFC 7489 section 6.6.1), the
//! send-as check on an authenticated submission, and the DKIM signer.
//!
//! A field name is matched the way the DKIM signer and verifier match it:
//! case-insensitively, with whitespace before the colon allowed (the
//! obsolete `From :` form of RFC 5322 section 4.5.4). Reading it more
//! strictly here than there would let a second, unnoticed From field ride
//! along under a signature or a DMARC pass.

use mail_parser::{HeaderForm, HeaderValue};

/// What the From field of a message says about its author.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Author {
	/// No From field, or one without any address in it.
	Missing,
	/// More than one From field (RFC 5322 section 3.6 allows exactly one).
	MultipleFields,
	/// The addresses of the single From field, in order.
	Addresses(Vec<String>),
}

/// The DMARC Author Domain of a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorDomain {
	/// No From field, no address, or an address without a usable domain.
	Missing,
	/// More than one From field, or one field naming more than one domain:
	/// there is no single domain whose owner can speak for the message.
	Multiple,
	/// The single domain, lowercased.
	One(String),
}

/// The unfolded values of every From field in the header block of `raw`,
/// or `None` when the header block is not UTF-8.
pub fn from_fields(raw: &[u8]) -> Option<Vec<String>> {
	named_fields(raw, "from")
}

/// The unfolded values of every field called `wanted` (any case) in the
/// header block of `raw`, in order, or `None` when the header block is not
/// UTF-8.
fn named_fields(raw: &[u8], wanted: &str) -> Option<Vec<String>> {
	let block = std::str::from_utf8(crate::util::header_block::split_at_blank_line(raw).0).ok()?;
	let mut fields = Vec::new();
	let mut current: Option<String> = None;
	for line in block.split_inclusive('\n') {
		let (line, had_line_feed) = match line.strip_suffix('\n') {
			Some(line) => (line, true),
			None => (line, false),
		};
		let line = if had_line_feed {
			line.strip_suffix('\r').unwrap_or(line)
		} else {
			line
		};
		if line.starts_with([' ', '\t']) {
			if let Some(value) = &mut current {
				value.push_str(line);
			}
			continue;
		}
		if let Some(value) = current.take() {
			fields.push(value);
		}
		if let Some((name, value)) = line.split_once(':')
			&& name
				.trim_end_matches([' ', '\t'])
				.eq_ignore_ascii_case(wanted)
		{
			current = Some(value.to_string());
		}
	}
	fields.extend(current);
	Some(fields)
}

/// Read the author of `raw` from its From field.
pub fn author(raw: &[u8]) -> Author {
	let Some(fields) = from_fields(raw) else {
		return Author::Missing;
	};
	match fields.as_slice() {
		[] => Author::Missing,
		[value] => {
			let addresses = addresses(value);
			if addresses.is_empty() {
				Author::Missing
			} else {
				Author::Addresses(addresses)
			}
		}
		_ => Author::MultipleFields,
	}
}

/// Every address of every From field of `raw`, in the lowercase form the
/// envelope holds. What a check keyed by sender asks about besides the
/// envelope sender, so a message is held to the lists of each address it
/// claims to come from. Empty when the header block is not UTF-8 or has none.
pub fn all_addresses(raw: &[u8]) -> Vec<String> {
	let mut out: Vec<String> = Vec::new();
	for value in from_fields(raw).unwrap_or_default() {
		for address in addresses(&value) {
			let address = crate::util::address::normalize(&address);
			if !out.contains(&address) {
				out.push(address);
			}
		}
	}
	out
}

/// Every address of every `Sender` field of `raw`, in the lowercase form the
/// envelope holds, read the way the From field is: all of the fields, not
/// the first, and every address of each. RFC 5322 allows one `Sender`, but a
/// message may carry more, and each is something the message says it was sent
/// by. Empty when the header block is not UTF-8 or has none.
pub fn all_sender_addresses(raw: &[u8]) -> Vec<String> {
	let mut out: Vec<String> = Vec::new();
	for value in named_fields(raw, "sender").unwrap_or_default() {
		for address in addresses(&value) {
			let address = crate::util::address::normalize(&address);
			if !out.contains(&address) {
				out.push(address);
			}
		}
	}
	out
}

/// The one address `raw` is written under, or `fallback` when it names none
/// or several. The tenant and the retention of a submission follow it, not
/// the envelope sender, which a caller may choose among the addresses it owns.
pub fn sole_address(raw: &[u8], fallback: &str) -> String {
	match author(raw) {
		Author::Addresses(addresses) if addresses.len() == 1 => {
			crate::util::address::normalize(&addresses[0])
		}
		_ => fallback.to_string(),
	}
}

/// The DMARC Author Domain of `raw`.
pub fn author_domain(raw: &[u8]) -> AuthorDomain {
	let addresses = match author(raw) {
		Author::Missing => return AuthorDomain::Missing,
		Author::MultipleFields => return AuthorDomain::Multiple,
		Author::Addresses(addresses) => addresses,
	};
	let mut domains: Vec<String> = Vec::new();
	for address in &addresses {
		let Some(domain) = domain_of(address) else {
			return AuthorDomain::Missing;
		};
		if !domains.contains(&domain) {
			domains.push(domain);
		}
	}
	match domains.as_slice() {
		[one] => AuthorDomain::One(one.clone()),
		_ => AuthorDomain::Multiple,
	}
}

/// Every address in one From field value, groups flattened.
fn addresses(value: &str) -> Vec<String> {
	let mut input = value.trim().to_string();
	input.push_str("\r\n");
	let parsed = HeaderForm::Addresses.parse(input.as_bytes());
	match parsed.value() {
		HeaderValue::Address(parsed) => parsed
			.mailboxes()
			.filter_map(|addr| addr.address())
			.map(|address| address.trim().to_string())
			.filter(|address| !address.is_empty())
			.collect(),
		_ => Vec::new(),
	}
}

/// The lowercased domain of `address`, when it has one a DNS name could be.
/// The value comes from a header, so it is data and is not held to the domain
/// rules: a domain of one label (`localhost`) is kept as it came, and the
/// DMARC lookup that follows finds no record for it.
fn domain_of(address: &str) -> Option<String> {
	let (local, domain) = address.rsplit_once('@')?;
	let domain = domain.trim().to_ascii_lowercase();
	let usable = !local.is_empty()
		&& !domain.is_empty()
		&& !domain
			.chars()
			.any(|c| c.is_whitespace() || c.is_control() || "()<>,;:\\\"[]@".contains(c));
	usable.then_some(domain)
}

#[cfg(test)]
mod tests;
