//! The one rule for what a credential label may be.
//!
//! An app password and an API key are each named by a label the operator
//! types. The label is printed by `list`, typed again to revoke or rotate, and
//! written into logs and audit lines, so it stays short and plain: not empty,
//! at most [`MAX_LEN`] characters, no control or invisible formatting character
//! and no space at either end. Inner spaces and non-ASCII letters are fine, so
//! `work phone` and `tel\u{e9}fono` are labels.
//!
//! The rule is a habit of the CLI, not a requirement of a standard, and a label
//! is never a secret. Every entry that creates or renames a credential calls
//! [`check`], so the two kinds of credential cannot drift apart.

use std::fmt;

/// Longest label, in characters.
pub const MAX_LEN: usize = 64;

/// Why a label is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fault {
	/// Nothing, or only spaces.
	Empty,
	/// A control character such as a newline or an escape.
	Control(char),
	/// An invisible formatting character such as a right-to-left override.
	Invisible(char),
	/// A space before the first or after the last visible character.
	EdgeSpace,
	/// More than [`MAX_LEN`] characters.
	TooLong(usize),
}

impl fmt::Display for Fault {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Fault::Empty => f.write_str("it is empty"),
			Fault::Control(c) => write!(f, "{c:?} is a control character"),
			Fault::Invisible(c) => write!(
				f,
				"{c:?} is an invisible formatting character (such as a right-to-left override)"
			),
			Fault::EdgeSpace => f.write_str("it starts or ends with a space"),
			Fault::TooLong(len) => {
				write!(f, "it is {len} characters long and the limit is {MAX_LEN}")
			}
		}
	}
}

/// The refusal of `label` as one line: the value, the rule it breaks and a
/// label that would be accepted. The value is cut and quoted with escapes, so
/// a control character in it cannot move the cursor of the terminal that
/// prints the message.
pub fn refusal(label: &str, fault: &Fault) -> String {
	let shown = crate::util::address_reason::shorten(label);
	format!(
		"label {shown:?}: {fault}; use 1 to {MAX_LEN} plain characters with no space at either end, for example \"work phone\""
	)
}

/// Whether `label` may name a credential.
pub fn check(label: &str) -> Result<(), Fault> {
	if label.trim().is_empty() {
		return Err(Fault::Empty);
	}
	if let Some(c) = label.chars().find(|c| c.is_control()) {
		return Err(Fault::Control(c));
	}
	if let Some(c) = label
		.chars()
		.find(|c| crate::util::validation::is_invisible_format(*c))
	{
		return Err(Fault::Invisible(c));
	}
	if label != label.trim() {
		return Err(Fault::EdgeSpace);
	}
	let len = label.chars().count();
	if len > MAX_LEN {
		return Err(Fault::TooLong(len));
	}
	Ok(())
}

/// [`check`] as the line the operator reads.
pub fn problem(label: &str) -> Option<String> {
	check(label).err().map(|fault| refusal(label, &fault))
}

#[cfg(test)]
mod tests;
