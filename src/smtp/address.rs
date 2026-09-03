//! Mailbox address validation (RFC 5321 section 4.1.2, strict subset).
//!
//! Quoted local parts and address literals are intentionally not accepted:
//! they are a recurring source of parser differentials and abuse, and real
//! mail rarely needs them. Strictness here is a feature.

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
}

impl Address {
	/// Parse and validate an address.
	pub fn parse(raw: &str) -> Result<Self, AddressError> {
		if raw.len() > MAX_ADDRESS {
			return Err(AddressError::TooLong);
		}
		let (local_part, domain) = raw.rsplit_once('@').ok_or(AddressError::MissingAtSign)?;
		validate_local_part(local_part)?;
		validate_domain(domain)?;
		Ok(Address {
			local_part: local_part.to_string(),
			// Domains compare case-insensitively; store lowercase.
			domain: domain.to_ascii_lowercase(),
		})
	}

	/// The (case-preserved) local part.
	pub fn local_part(&self) -> &str {
		&self.local_part
	}

	/// The lowercased domain.
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

fn validate_domain(domain: &str) -> Result<(), AddressError> {
	// RFC 5321 §4.5.3.1.2 caps a domain at 255 octets and the section
	// header requires implementations to accept names of at least that
	// size. 255 is the wire form: each label carries a length byte and
	// the root label adds one more, so any presentation name is exactly
	// two octets shorter than its wire encoding. 253 is the longest dot-
	// separated string the wire cap can carry; raising this check would
	// accept names that no DNS query can resolve.
	if domain.is_empty() || domain.len() > 253 || !domain.contains('.') {
		return Err(AddressError::InvalidDomain);
	}
	for label in domain.split('.') {
		let valid = !label.is_empty()
			&& label.len() <= 63
			&& !label.starts_with('-')
			&& !label.ends_with('-')
			&& label.chars().all(|c| {
				c.is_ascii_alphanumeric() || c == '-' || (!c.is_ascii() && !c.is_control())
			});
		if !valid {
			return Err(AddressError::InvalidDomain);
		}
	}
	Ok(())
}

#[cfg(test)]
#[path = "address_tests.rs"]
mod tests;
