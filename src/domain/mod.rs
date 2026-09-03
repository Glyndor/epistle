//! Domain normalisation: every domain that crosses the boundary becomes a
//! lowercase ASCII A-label, or it is rejected.
//!
//! Storage and lookup keys everywhere in epistle (`Address::domain`, the
//! directory's domain set, tenant domain maps, the acme and dns record
//! generators, DKIM `d=` comparisons, MTA-STS) are A-labels. Inputs arrive as
//! either ASCII or as Unicode U-labels (`bücher.example`); two spellings of one
//! domain must hash to the same key, and a Cyrillic look-alike of a Latin name
//! must not be accepted in the first place.
//!
//! [`normalize`] is the single point of entry: it does every script and
//! confusable check on the U-label form, runs UTS 46 strict to produce the
//! A-label, and re-validates the wire shape on the result. Any caller that
//! stores a domain stores the returned string verbatim.

use unicode_security::confusable_detection::skeleton;
use unicode_security::mixed_script::MixedScript;

/// Why a domain was refused by [`normalize`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainError {
	/// Empty, too long, a bad label, control character, invalid punycode, or
	/// an A-label that fails the DNS shape check on the wire form.
	Invalid,
	/// A label mixes scripts, or its skeleton is pure ASCII while the label
	/// itself is not (Unicode TR39). The label is built to look like another
	/// name that the operator does not control.
	Confusable,
}

/// Maximum presentation-form length (RFC 1035 section 2.3.4: the wire form is
/// at most 255 octets, the trailing root label takes one, and each label
/// carries a length byte; the longest dot-separated presentation string is
/// therefore 253 octets).
const MAX_DOMAIN: usize = 253;
/// Per-label length cap (RFC 1035 section 2.3.4).
const MAX_LABEL: usize = 63;

/// Normalise a domain to its lowercase ASCII A-label form, rejecting names
/// that cannot resolve and names built to look like another one.
///
/// Steps, in this order, and the order is the contract:
/// 1. reject empty input, ASCII whitespace, and control characters;
/// 2. reject a label that mixes scripts or whose skeleton is pure ASCII
///    while the label is not (Unicode TR39), on the U-label form;
/// 3. convert to ASCII with UTS 46 (`idna::domain_to_ascii_strict`,
///    which also applies DNS length checks and the STD3 hyphen rules);
/// 4. lowercase again (cheap, and it makes the guarantee local);
/// 5. apply the DNS shape rules on the result: total length at most 253,
///    at least one dot, every label 1..=63 of `[a-z0-9-]` not starting or
///    ending with `-`.
pub fn normalize(raw: &str) -> Result<String, DomainError> {
	if raw.is_empty()
		|| raw.bytes().any(|b| b.is_ascii_whitespace())
		|| raw.chars().any(|c| c.is_control())
	{
		return Err(DomainError::Invalid);
	}
	check_confusables(raw)?;
	let ascii = idna::domain_to_ascii_strict(raw).map_err(|_| DomainError::Invalid)?;
	let ascii = ascii.to_ascii_lowercase();
	check_dns_shape(&ascii)?;
	Ok(ascii)
}

/// Unicode TR39 mixed-script and confusable-skeleton checks, applied to the
/// U-label form. For a label already in `xn--` form the punycode body is
/// decoded first so the check sees the underlying Unicode; a pure-ASCII
/// label skips both checks.
fn check_confusables(raw: &str) -> Result<(), DomainError> {
	for label in raw.split('.') {
		if label.is_empty() {
			continue;
		}
		let lower = label.to_ascii_lowercase();
		let unicode = if let Some(body) = lower.strip_prefix("xn--") {
			idna::punycode::decode_to_string(body).ok_or(DomainError::Invalid)?
		} else if label.is_ascii() {
			continue;
		} else {
			label.to_string()
		};
		if !unicode.is_single_script() {
			return Err(DomainError::Confusable);
		}
		let skel: String = skeleton(&unicode).collect();
		if !unicode.is_ascii() && skel.is_ascii() {
			return Err(DomainError::Confusable);
		}
	}
	Ok(())
}

/// Wire-shape check applied to the A-label result: at least one dot, total
/// length at most [`MAX_DOMAIN`], every label 1..=[`MAX_LABEL`] of
/// `[a-z0-9-]` and not starting or ending with `-`.
fn check_dns_shape(ascii: &str) -> Result<(), DomainError> {
	if !ascii.contains('.') || ascii.len() > MAX_DOMAIN {
		return Err(DomainError::Invalid);
	}
	for label in ascii.split('.') {
		if label.is_empty()
			|| label.len() > MAX_LABEL
			|| label.starts_with('-')
			|| label.ends_with('-')
			|| !label
				.bytes()
				.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
		{
			return Err(DomainError::Invalid);
		}
	}
	Ok(())
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
