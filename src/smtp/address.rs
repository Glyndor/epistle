//! Mailbox address validation (RFC 5321 section 4.1.2, strict subset).
//!
//! Quoted local parts and address literals are intentionally not accepted:
//! they are a recurring source of parser differentials and abuse, and real
//! mail rarely needs them. Strictness here is a feature.

use crate::domain::{DomainError, normalize};

/// Maximum total address length (RFC 5321 section 4.5.3.1.3).
const MAX_ADDRESS: usize = 254;
/// Maximum local-part length (RFC 5321 section 4.5.3.1.1).
const MAX_LOCAL_PART: usize = 64;

/// A validated `local-part@domain` address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
	local_part: String,
	domain: String,
}

/// Why an address was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressError {
	/// The address exceeded the RFC 5321 §4.5.3.1.3 total length cap (254
	/// octets).
	TooLong,
	/// The address had no `@` to separate the local part from the domain.
	MissingAtSign,
	/// The local part was empty, overlong, contained a disallowed character,
	/// had consecutive dots, or was a quoted-string form (deliberately
	/// refused by this strict parser).
	InvalidLocalPart,
	/// The domain was empty, had no dot, contained an overlong label, a
	/// leading/trailing hyphen, an underscore, or an address-literal form
	/// (deliberately refused).
	InvalidDomain,
	/// The domain mixed scripts, or its Unicode skeleton reduced to an all-ASCII
	/// name (Unicode TR39): it was built to look like another address that
	/// this server does not control.
	ConfusableDomain,
}

impl Address {
	/// Parse and validate an address. The stored `domain` is the lowercase
	/// ASCII A-label returned by [`crate::domain::normalize`]: two
	/// spellings of one internationalised domain land on the same key, and
	/// a Cyrillic look-alike of a Latin name is refused before it ever
	/// becomes a string the rest of the server can compare.
	pub fn parse(raw: &str) -> Result<Self, AddressError> {
		if raw.len() > MAX_ADDRESS {
			return Err(AddressError::TooLong);
		}
		let (local_part, domain) = raw.rsplit_once('@').ok_or(AddressError::MissingAtSign)?;
		validate_local_part(local_part)?;
		let domain = normalize(domain).map_err(|err| match err {
			DomainError::Invalid => AddressError::InvalidDomain,
			DomainError::Confusable => AddressError::ConfusableDomain,
		})?;
		Ok(Address {
			local_part: local_part.to_string(),
			domain,
		})
	}

	/// The (case-preserved) local part.
	pub fn local_part(&self) -> &str {
		&self.local_part
	}

	/// The lowercase A-label of the domain.
	pub fn domain(&self) -> &str {
		&self.domain
	}
}

impl std::fmt::Display for Address {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{}@{}", self.local_part, self.domain)
	}
}

/// Dot-string per RFC 5321: atoms separated by single dots.
fn validate_local_part(local_part: &str) -> Result<(), AddressError> {
	if local_part.is_empty() || local_part.len() > MAX_LOCAL_PART {
		return Err(AddressError::InvalidLocalPart);
	}
	// Internationalized local parts (RFC 6531/SMTPUTF8): atom characters plus
	// any non-ASCII, non-control UTF-8 (control characters stay forbidden).
	let valid_atom_char = |c: char| {
		c.is_ascii_alphanumeric()
			|| "!#$%&'*+-/=?^_`{|}~".contains(c)
			|| (!c.is_ascii() && !c.is_control())
	};
	for atom in local_part.split('.') {
		if atom.is_empty() || !atom.chars().all(valid_atom_char) {
			return Err(AddressError::InvalidLocalPart);
		}
	}
	Ok(())
}

#[cfg(test)]
#[path = "address_tests.rs"]
mod tests;
