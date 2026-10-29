//! The character sets and the bounds that more than one input rule needs.
//!
//! Several validation rules are about the same handful of facts and used to
//! spell those facts out again at each call site: the characters a mail local
//! part may carry (RFC 5321 `atext`), the characters that reorder or hide text
//! without being control characters, the length caps RFC 5321 and RFC 1035
//! put on an address, a domain and a label, and the shape of a memory size
//! the stack compose file writes.
//!
//! They live here so a rule states the *addition* it makes and takes the base
//! from one place. A caller that needs `atext` plus a dot, or `atext` plus a
//! space (an RFC 5322 phrase rather than an address), composes the two here
//! instead of retyping the nineteen characters.
//!
//! This module holds no rule of its own: it decides nothing that accepts or
//! refuses an input on its own. [`crate::smtp::address::Address::parse`],
//! [`crate::domain::normalize`] and each consumer keep that decision.

/// The non-alphanumeric characters an RFC 5321 section 4.1.2 dot-atom may
/// carry, next to ASCII letters and digits: `atext` minus `ALPHA` and
/// `DIGIT`. Nineteen characters, none of them a dot (the dot is the atom
/// separator, checked separately by every caller that allows it).
pub const ATEXT: &str = "!#$%&'*+-/=?^_`{|}~";

/// Whether `c` may appear in an RFC 5321 dot-atom: an ASCII letter or digit,
/// one of [`ATEXT`], or, for a server that advertises SMTPUTF8 (RFC 6531),
/// any non-ASCII character that is not a control and not a Unicode line or
/// paragraph separator. `char::is_control` covers the C0 and C1 ranges only,
/// and U+2028 and U+2029 break a log line and some clients the way a newline
/// does, so they are refused here, as the Sieve script name and mailbox name
/// rules already refuse them.
pub fn is_atext(c: char) -> bool {
	c.is_ascii_alphanumeric()
		|| ATEXT.contains(c)
		|| (!c.is_ascii() && !c.is_control() && !matches!(c, '\u{2028}' | '\u{2029}'))
}

/// Whether `text` carries the Unicode line or paragraph separator (U+2028,
/// U+2029). They are not `char::is_control`, so the paths that take an address
/// without running it through [`crate::smtp::address::Address::parse`] (the
/// static alias table, the structured addresses of a JMAP `Email/set`) use
/// this to refuse them the way the parser does.
pub fn has_line_separator(text: &str) -> bool {
	text.chars().any(|c| matches!(c, '\u{2028}' | '\u{2029}'))
}

/// [`is_atext`] over octets, for the callers that walk raw bytes. A byte is
/// never non-ASCII in the UTF-8 sense (each octet of a multi-byte sequence
/// stands for itself), so this is the ASCII half only: an RFC 6531 local part
/// has to be checked as `char`.
pub fn is_atext_byte(b: u8) -> bool {
	b.is_ascii_alphanumeric() || ATEXT.as_bytes().contains(&b)
}

/// Whether `c` is an invisible formatting character that makes text read
/// differently from what it is: the Arabic letter mark, the left-to-right and
/// right-to-left marks, the embedding, override and isolate controls, and the
/// deprecated format controls around them. A name carrying one of these can
/// be made to look like another name.
///
/// This is the set a *name* is refused for. It is deliberately narrower than
/// [`crate::evidence::hidden::is_hidden`], which covers the whole Unicode
/// format category and the default-ignorable code points, and than
/// `cli::term::is_invisible_format`, which adds what a terminal would draw as
/// blank.
pub fn is_bidi_or_invisible(c: char) -> bool {
	matches!(
		c,
		'\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
	)
}

/// Whether `c` reorders, hides or blanks text without being a control
/// character: the whole Unicode format category, the Unicode line and
/// paragraph separators, and the default-ignorable code points. This is the
/// set a *label* is refused for, because a label is printed back by `list`
/// and written to logs. It is the set of
/// [`crate::evidence::hidden::is_hidden`], named here so the rules under
/// `util` do not reach into a terminal module for it.
pub fn is_invisible_format(c: char) -> bool {
	crate::evidence::hidden::is_hidden(c)
}

/// Longest address, in octets, without the angle brackets (RFC 5321 section
/// 4.5.3.1.3: the longest path is 256 octets with them).
pub const MAX_ADDRESS: usize = 254;

/// Longest local part, in octets (RFC 5321 section 4.5.3.1.1).
pub const MAX_LOCAL_PART: usize = 64;

/// Longest domain in presentation form, the trailing root label excluded
/// (RFC 1035 section 2.3.4: the wire form is at most 255 octets and each
/// label carries a length byte).
pub const MAX_DOMAIN: usize = 253;

/// Longest single label of a domain, in octets (RFC 1035 section 2.3.4).
pub const MAX_LABEL: usize = 63;

/// Whether `value` is written the way the stack compose file writes a memory
/// size: a whole number of `k`, `m` or `g` (any case), above zero.
///
/// This is the *shape* only. A value of the right shape that no 64-bit size
/// reaches is still a shape, and `epistle stack resources set` answers that
/// case with its own message rather than with this one, so the two checks stay
/// separate. [`parse_memory_size`] is the one that reads the number.
pub fn is_memory_size_shape(value: &str) -> bool {
	let Some(last) = value.len().checked_sub(1) else {
		return false;
	};
	let (digits, unit) = value.split_at(last);
	matches!(unit, "k" | "K" | "m" | "M" | "g" | "G")
		&& !digits.is_empty()
		&& digits.bytes().all(|byte| byte.is_ascii_digit())
		&& digits.bytes().any(|byte| byte != b'0')
}

/// A memory size as the stack compose file and the host reports it, read as the
/// byte count it stands for. `None` for anything that is not the shape above,
/// for a zero result, and for a value no 64-bit size reaches.
pub fn parse_memory_size(value: &str) -> Option<u64> {
	let (digits, unit) = value.split_at_checked(value.len().checked_sub(1)?)?;
	let scale: u64 = match unit {
		"k" | "K" => 1024,
		"m" | "M" => 1024 * 1024,
		"g" | "G" => 1024 * 1024 * 1024,
		_ => return None,
	};
	if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
		return None;
	}
	digits
		.parse::<u64>()
		.ok()
		.and_then(|number| number.checked_mul(scale))
		.filter(|bytes| *bytes > 0)
}

#[cfg(test)]
mod tests;
