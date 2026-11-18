//! One line of `podup logs`: `<container> | [<time> ]<message>`.

use std::borrow::Cow;

use super::stamp;

/// The longest message, in characters, a line keeps unless `--raw` is given.
pub(super) const LINE_LIMIT: usize = 500;

/// Where the message of `line` starts: after the container name and its
/// ` | ` and, when podup was asked for them, after the time.
fn message_start(line: &str) -> usize {
	let after_name = line.find(" | ").map_or(0, |at| at + 3);
	let rest = &line[after_name..];
	match rest.split_once(' ') {
		Some((token, _)) if stamp::parse(token).is_some() => after_name + token.len() + 1,
		_ => after_name,
	}
}

/// The time at the start of the message part of `line`, if podup printed one.
pub(super) fn stamp_of(line: &str) -> Option<i128> {
	let after_name = line.find(" | ").map_or(0, |at| at + 3);
	let (token, _) = line[after_name..].split_once(' ')?;
	stamp::parse(token)
}

/// `line` with a message longer than `limit` characters cut at the limit and
/// a mark that says how many bytes were left out. `omitted` is how many bytes
/// the reader dropped after `line`, which are left out as well.
pub(super) fn cut(line: &str, limit: usize, omitted: u64) -> Cow<'_, str> {
	let start = message_start(line);
	let message = &line[start..];
	let keep = message
		.char_indices()
		.nth(limit)
		.map_or(message.len(), |(at, _)| at);
	let left_out = (message.len() - keep) as u64 + omitted;
	if left_out == 0 {
		return Cow::Borrowed(line);
	}
	Cow::Owned(format!(
		"{}{} [{left_out} more bytes cut; --raw shows them]",
		&line[..start],
		&message[..keep]
	))
}
