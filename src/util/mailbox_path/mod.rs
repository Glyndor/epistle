//! Hierarchical mailbox names (`Work/Project`) and their on-disk spelling.
//!
//! A stored mailbox name is in modified UTF-7 (RFC 3501 §5.1.3) and may hold
//! the hierarchy delimiter `/`. Each level between two delimiters follows the
//! folder alphabet: ASCII letters, digits, space, `-`, `_` and `.`, plus
//! non-ASCII characters in their modified UTF-7 spelling; a level is never
//! empty, never starts with `.` and never ends with a space.
//!
//! Folders stay flat on disk: one directory under `folders/` per mailbox,
//! whatever its depth. The directory is named after the stored name with every
//! `/` written as `&AC8-`, the modified UTF-7 run that decodes to `/`. That
//! mapping is a bijection: a valid stored name can never contain `&AC8-`,
//! because its levels are canonical modified UTF-7 and `/` is printable ASCII,
//! which the canonical form never encodes. [`disk_name`] and [`stored_name`]
//! are the only conversions between the two spellings.
//!
//! Limits, so a client cannot make a name expensive to store or walk:
//! [`MAX_DEPTH`] levels, [`super::path_component`]'s per-component limit for
//! each level, and [`MAX_DISK_NAME_LEN`] bytes for the directory name.

use std::borrow::Cow;

use super::path_component::is_plain_component;

/// The hierarchy delimiter LIST reports and names use.
pub const DELIMITER: char = '/';

/// The modified UTF-7 spelling of the delimiter, used in directory names.
const DISK_DELIMITER: &str = "&AC8-";

/// Most levels a mailbox name may have (`a/b/c` has three).
pub const MAX_DEPTH: usize = 16;

/// Longest on-disk directory name for a mailbox, in bytes: `NAME_MAX` of the
/// common Linux filesystems (ext4, XFS, Btrfs).
pub const MAX_DISK_NAME_LEN: usize = 255;

/// Whether `name` is a valid stored name for a folder: every level valid,
/// at most [`MAX_DEPTH`] levels, an on-disk name of at most
/// [`MAX_DISK_NAME_LEN`] bytes, and not the inbox itself. `INBOX/child` is a
/// folder (the first level matches `INBOX` in any case).
pub fn valid_folder(name: &str) -> bool {
	if name.eq_ignore_ascii_case("INBOX") || name.contains(DISK_DELIMITER) {
		return false;
	}
	let mut depth = 0;
	for level in name.split(DELIMITER) {
		depth += 1;
		if depth > MAX_DEPTH || !valid_level(level) {
			return false;
		}
	}
	disk_len(name) <= MAX_DISK_NAME_LEN
}

/// One level of a hierarchical name, in its stored (modified UTF-7) spelling.
fn valid_level(level: &str) -> bool {
	if !is_plain_component(level) || level.starts_with('.') {
		return false;
	}
	// The decoded level carries ASCII letters, digits, space, `-`, `_` and
	// `.`, plus any non-ASCII character that is not a control or a
	// line/paragraph separator (Net-Unicode, RFC 5198).
	super::mutf7::decode(level).is_some_and(|decoded| {
		decoded.chars().all(|c| {
			c.is_ascii_alphanumeric()
				|| matches!(c, ' ' | '-' | '_' | '.')
				|| (!c.is_ascii() && !c.is_control() && !matches!(c, '\u{2028}' | '\u{2029}'))
		}) && !decoded.ends_with(' ')
	})
}

fn disk_len(name: &str) -> usize {
	name.len() + name.matches(DELIMITER).count() * (DISK_DELIMITER.len() - 1)
}

/// `name` with a first level equal to `INBOX` in any case spelled `INBOX`, so
/// `inbox/x` and `INBOX/x` are one mailbox. Every other level keeps its case.
pub fn canonical(name: &str) -> Cow<'_, str> {
	match name.split_once(DELIMITER) {
		Some((first, rest)) if first.eq_ignore_ascii_case("INBOX") && first != "INBOX" => {
			Cow::Owned(format!("INBOX{DELIMITER}{rest}"))
		}
		_ => Cow::Borrowed(name),
	}
}

/// The directory name under `folders/` for the stored name `name`: the
/// canonical name with every `/` written as `&AC8-`. The result never holds
/// a `/`, so it is always one path component.
pub fn disk_name(name: &str) -> String {
	canonical(name).replace(DELIMITER, DISK_DELIMITER)
}

/// The stored name a directory under `folders/` holds, or `None` when the
/// directory name is not exactly what [`disk_name`] makes of a valid name.
pub fn stored_name(disk: &str) -> Option<String> {
	let name = disk.replace(DISK_DELIMITER, "/");
	(valid_folder(&name) && disk_name(&name) == disk).then_some(name)
}

/// The parent of `name` (`a/b` for `a/b/c`), or `None` at the top level.
pub fn parent(name: &str) -> Option<&str> {
	name.rsplit_once(DELIMITER).map(|(parent, _)| parent)
}

/// The last level of `name` (`c` for `a/b/c`).
pub fn leaf(name: &str) -> &str {
	name.rsplit_once(DELIMITER).map_or(name, |(_, leaf)| leaf)
}

/// Every proper ancestor of `name`, shortest first (`a`, `a/b` for `a/b/c`).
pub fn ancestors(name: &str) -> impl DoubleEndedIterator<Item = &str> {
	name.match_indices(DELIMITER).map(|(at, _)| &name[..at])
}

/// The closest ancestor of `name` that `exists` accepts, or `None`. Used to
/// show a folder under the nearest mailbox that is really there, when a level
/// in between is missing.
pub fn nearest_parent(name: &str, exists: impl Fn(&str) -> bool) -> Option<&str> {
	ancestors(name).rev().find(|ancestor| exists(ancestor))
}

/// The last level of `name` as a person reads it: decoded from modified
/// UTF-7 (`Año` for `Work/A&APE-o`), or as stored if it does not decode.
pub fn display_leaf(name: &str) -> String {
	let leaf = leaf(name);
	super::mutf7::decode(leaf).unwrap_or_else(|| leaf.to_string())
}

/// The stored name of the folder `level` (a UTF-8 name of one level) under
/// `parent`, or under the top level for `None`. `None` when `level` is empty
/// or holds the delimiter; whether the result is a valid name is up to the
/// caller.
pub fn child_of(parent: Option<&str>, level: &str) -> Option<String> {
	if level.is_empty() || level.contains(DELIMITER) {
		return None;
	}
	let level = super::mutf7::encode(level);
	Some(match parent {
		Some(parent) => format!("{parent}{DELIMITER}{level}"),
		None => level,
	})
}

/// Whether `name` is `ancestor` or lies below it.
pub fn is_within(name: &str, ancestor: &str) -> bool {
	name.strip_prefix(ancestor)
		.is_some_and(|rest| rest.is_empty() || rest.starts_with(DELIMITER))
}

#[cfg(test)]
mod tests;
