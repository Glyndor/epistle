//! The one rule for what an account may be called, and how a name is
//! derived from an address.
//!
//! The account name is also the folder name under `<data_dir>/accounts/`, so
//! it stays boring: lowercase ASCII letters, digits and hyphens, not
//! starting with a hyphen, at most [`MAX_LEN`] characters. An address is
//! more permissive (RFC 5322 allows a dot in the local part), so the name is
//! derived from the address rather than the address being made to obey the
//! folder rule: `torre.control` becomes `torre-control`.
//!
//! `init`, the configuration validator and the account store all call this
//! module, so the three cannot drift apart.

use std::fmt;

/// Longest account name, in characters.
pub const MAX_LEN: usize = 64;

/// Why a name, or the local part an address would give it, is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fault {
	/// Nothing to name the account after.
	Empty,
	/// More than [`MAX_LEN`] characters.
	TooLong(usize),
	/// Starts with a hyphen.
	LeadingHyphen,
	/// A character outside lowercase letters, digits and hyphens.
	BadChar(char),
	/// The local part starts with a dot.
	DotAtStart,
	/// The local part ends with a dot.
	DotAtEnd,
	/// The local part has two dots in a row.
	DoubleDot,
}

impl fmt::Display for Fault {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Fault::Empty => f.write_str("it is empty"),
			Fault::TooLong(len) => {
				write!(f, "it is {len} characters long and the limit is {MAX_LEN}")
			}
			Fault::LeadingHyphen => f.write_str("it must not start with a hyphen"),
			Fault::BadChar(c) if c.is_ascii_uppercase() => write!(
				f,
				"{c:?} is a capital letter; names are lowercase"
			),
			Fault::BadChar(c) if c.is_uppercase() => write!(
				f,
				"{c:?} is a capital letter outside ASCII; an account name has lowercase ASCII letters, digits and hyphens only"
			),
			Fault::BadChar('.') => f.write_str(
				"'.' is not allowed in an account name, which has lowercase letters, digits and hyphens only; use a hyphen",
			),
			Fault::BadChar(c) => write!(
				f,
				"{c:?} is not allowed; an account name has lowercase letters, digits and hyphens only"
			),
			Fault::DotAtStart => f.write_str("the part before @ starts with a dot"),
			Fault::DotAtEnd => f.write_str("the part before @ ends with a dot"),
			Fault::DoubleDot => f.write_str("the part before @ has two dots in a row"),
		}
	}
}

/// The refusal of `name` as one line: the name and why, or just that the
/// name is empty (quoting an empty name adds nothing).
pub fn refusal(name: &str, fault: &Fault) -> String {
	match fault {
		Fault::Empty => "account name must not be empty".to_string(),
		_ => format!("account name \"{name}\": {fault}"),
	}
}

/// Whether `name` is an account name as stored: the folder-name rule.
pub fn check(name: &str) -> Result<(), Fault> {
	if name.is_empty() {
		return Err(Fault::Empty);
	}
	if let Some(bad) = name
		.chars()
		.find(|c| !(c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '-'))
	{
		return Err(Fault::BadChar(bad));
	}
	if name.starts_with('-') {
		return Err(Fault::LeadingHyphen);
	}
	let len = name.chars().count();
	if len > MAX_LEN {
		return Err(Fault::TooLong(len));
	}
	Ok(())
}

/// The account name an address gives: its local part in lowercase, with
/// each dot turned into a hyphen. A dot at the start, at the end or twice in
/// a row is refused, and so is any other character the name rule does not
/// allow, which the fault names.
pub fn derive(local_part: &str) -> Result<String, Fault> {
	if local_part.starts_with('.') {
		return Err(Fault::DotAtStart);
	}
	if local_part.ends_with('.') {
		return Err(Fault::DotAtEnd);
	}
	if local_part.contains("..") {
		return Err(Fault::DoubleDot);
	}
	let name = local_part.to_ascii_lowercase().replace('.', "-");
	check(&name)?;
	Ok(name)
}

#[cfg(test)]
#[path = "account_rule_tests.rs"]
mod tests;
