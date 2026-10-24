//! The RFC5322.From field of a message, read once and the same way for
//! every consumer: the DMARC Author Domain (RFC 7489 section 6.6.1), the
//! send-as check on an authenticated submission, and the DKIM signer.
//!
//! A field name is matched the way the DKIM signer and verifier match it:
//! case-insensitively, with whitespace before the colon allowed (the
//! obsolete `From :` form of RFC 5322 section 4.5.4). Reading it more
//! strictly here than there would let a second, unnoticed From field ride
//! along under a signature or a DMARC pass.

use mail_parser::HeaderValue;
use mail_parser::parsers::MessageStream;

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
	let end = raw
		.windows(4)
		.position(|w| w == b"\r\n\r\n")
		.map(|p| p + 2)
		.unwrap_or(raw.len());
	let block = std::str::from_utf8(&raw[..end]).ok()?;
	let mut fields = Vec::new();
	let mut current: Option<String> = None;
	for line in block.split("\r\n") {
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
				.eq_ignore_ascii_case("from")
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
	match MessageStream::new(input.as_bytes()).parse_address() {
		HeaderValue::Address(parsed) => parsed
			.iter()
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
#[path = "author_tests.rs"]
mod tests;
