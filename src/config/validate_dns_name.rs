//! The rule for a host or domain name written in `mail.toml`.
//!
//! Pulled into a sibling so `validate.rs` stays under the per-file line
//! limit; `Config::validate` and the commands that edit the file call it.

use super::ConfigError;

/// Validate a fully qualified DNS name; `field` names it in errors.
///
/// Every value on disk is stored verbatim after this call returns `Ok`,
/// but the caller (`Config::validate_domains` and friends) lowercases it
/// before insertion into a domain-keyed set, so an operator who writes
/// `Example.org` and `example.org` ends up with one entry. A U-label
/// (any non-ASCII domain) is refused here with the A-label the operator
/// should write instead, so configuration stays ASCII on disk and the
/// boundary is enforced in exactly one place.
pub(crate) fn validate_dns_name(field: &str, name: &str) -> Result<(), ConfigError> {
	let name = name.trim();
	let example = if matches!(field, "hostname" | "acme domain") {
		"mail.example.org"
	} else {
		"example.org"
	};
	if name.is_empty() {
		return Err(ConfigError::Invalid(format!(
			"{field} must not be empty; for example {example:?}"
		)));
	}
	let shown = crate::util::address_reason::shorten(name);
	// ASCII input still flows through normalize so the wire-shape rules
	// apply uniformly; a clean ASCII form comes back unchanged and is
	// accepted as today. A non-ASCII form that successfully normalises is
	// refused with the ASCII form the operator should write instead, so
	// configuration stays ASCII on disk.
	match crate::domain::normalize(name) {
		Ok(_) if name.is_ascii() => Ok(()),
		Ok(ascii) => Err(ConfigError::Invalid(format!(
			"{field} {shown:?} must be written as its ASCII form \"{ascii}\""
		))),
		Err(why) => Err(ConfigError::Invalid(format!(
			"{field} {shown:?}: {}",
			crate::util::address_reason::name_refusal(name, why, example)
		))),
	}
}
