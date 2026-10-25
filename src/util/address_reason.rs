//! Why an address or a domain was refused, in a short message an operator
//! can act on.
//!
//! [`crate::smtp::address::Address::parse`] decides what is accepted; this
//! module never changes that. It runs only after a value was refused and
//! names the first rule the value breaks ("local part is 65 characters; the
//! maximum is 64 (RFC 5321)") instead of repeating the whole value back.
//! Any part of the input it quotes is cut to [`ECHO_LIMIT`] characters, so a
//! 500-character paste does not come back as a 500-character error.

use crate::smtp::address::Address;
use crate::util::validation::{MAX_ADDRESS, MAX_DOMAIN, MAX_LABEL, MAX_LOCAL_PART, is_atext};

/// How many characters of a refused value a message quotes before cutting
/// it with an ellipsis.
pub const ECHO_LIMIT: usize = 40;

/// Parse an address, or say why it is not one.
pub fn parse(raw: &str) -> Result<Address, String> {
	Address::parse(raw).map_err(|_| reason(raw))
}

/// Cut `value` to [`ECHO_LIMIT`] characters, marking the cut with an ellipsis.
pub fn shorten(value: &str) -> String {
	if value.chars().count() <= ECHO_LIMIT {
		return value.to_string();
	}
	let mut cut: String = value.chars().take(ECHO_LIMIT).collect();
	cut.push('\u{2026}');
	cut
}

/// The refusal for an address in a domain this server does not serve.
pub fn not_handled(domain: &str) -> String {
	format!("{} is not a domain this server handles", shorten(domain))
}

/// Length unit for a message: an ASCII value is counted in characters, any
/// other in bytes, because the limits are octet limits.
fn length(value: &str) -> (usize, &'static str) {
	if value.is_ascii() {
		(value.len(), "characters")
	} else {
		(value.len(), "bytes")
	}
}

/// The first rule `raw` breaks as an address, in the order the parser checks.
pub fn reason(raw: &str) -> String {
	let (len, unit) = length(raw);
	if len > MAX_ADDRESS {
		return format!("the address is {len} {unit}; the maximum is {MAX_ADDRESS} (RFC 5321)");
	}
	if raw.chars().any(char::is_whitespace) {
		return "spaces are not allowed".to_string();
	}
	if raw.contains('"') {
		return "quoted local parts are not accepted".to_string();
	}
	let Some((local, domain)) = raw.rsplit_once('@') else {
		return format!("{} has no @", shorten(raw));
	};
	if local.contains('@') {
		return "only one @ is allowed".to_string();
	}
	if let Some(why) = local_part_reason(local) {
		return why;
	}
	domain_reason(domain)
}

/// The first rule `local` breaks as a local part, or `None` when it is valid.
fn local_part_reason(local: &str) -> Option<String> {
	if local.is_empty() {
		return Some("the local part before @ is empty".to_string());
	}
	let (len, unit) = length(local);
	if len > MAX_LOCAL_PART {
		return Some(format!(
			"local part is {len} {unit}; the maximum is {MAX_LOCAL_PART} (RFC 5321)"
		));
	}
	if local.starts_with('.') {
		return Some("the local part starts with a dot".to_string());
	}
	if local.ends_with('.') {
		return Some("the local part ends with a dot".to_string());
	}
	if local.contains("..") {
		return Some("consecutive dots in the local part".to_string());
	}
	// `atext` plus the dot that separates the atoms of a dot-string.
	let allowed = |c: char| is_atext(c) || c == '.';
	local
		.chars()
		.find(|c| !allowed(*c))
		.map(|c| format!("the character {c:?} is not allowed in the local part"))
}

/// The first rule `domain` breaks as a mail domain.
pub fn domain_reason(domain: &str) -> String {
	if domain.is_empty() {
		return "the domain after @ is empty".to_string();
	}
	if domain.chars().any(char::is_whitespace) {
		return "spaces are not allowed".to_string();
	}
	if domain.starts_with('[') {
		return "address literals are not accepted".to_string();
	}
	if domain.ends_with('.') {
		return "the domain ends with a dot".to_string();
	}
	let (len, unit) = length(domain);
	if len > MAX_DOMAIN {
		return format!("the domain is {len} {unit}; the maximum is {MAX_DOMAIN}");
	}
	if !domain.contains('.') {
		return format!("the domain {} needs at least one dot", shorten(domain));
	}
	for label in domain.split('.') {
		if label.is_empty() {
			return "consecutive dots in the domain".to_string();
		}
		let (len, unit) = length(label);
		if label.is_ascii() && len > MAX_LABEL {
			return format!(
				"the domain label '{}' is {len} {unit}; the maximum is {MAX_LABEL}",
				shorten(label)
			);
		}
		if label.starts_with('-') || label.ends_with('-') {
			return format!(
				"the domain label '{}' starts or ends with a hyphen",
				shorten(label)
			);
		}
		if let Some(c) = label
			.chars()
			.find(|c| c.is_ascii() && !(c.is_ascii_alphanumeric() || *c == '-'))
		{
			return format!("the character {c:?} is not allowed in a domain");
		}
	}
	match crate::domain::normalize(domain) {
		Err(crate::domain::DomainError::Confusable) => format!(
			"the domain {} mixes scripts or imitates another name",
			shorten(domain)
		),
		_ => format!("{} is not a valid domain", shorten(domain)),
	}
}

/// What an operator reads when a typed domain or host name is refused: the
/// rule `value` breaks and a name that would be accepted. Every place that
/// refuses a name the operator typed (the first-run assistant, the answers
/// file, the zone of a DNS provider) goes through this, so none of them says
/// only that the name is "not valid".
///
/// The reason may or may not quote the value, so the caller puts the value in
/// front of it when the message has no other place for it.
pub fn name_refusal(value: &str, why: crate::domain::DomainError, example: &str) -> String {
	let reason = match why {
		crate::domain::DomainError::Invalid => domain_reason(value),
		crate::domain::DomainError::Confusable => {
			"it is confusable with another name because it mixes scripts or imitates one; write it in a single script".to_string()
		}
	};
	format!("{reason}; for example {example:?}")
}

#[cfg(test)]
#[path = "address_reason_tests.rs"]
mod tests;
