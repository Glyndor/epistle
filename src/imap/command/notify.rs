//! Parsing for the RFC 5465 NOTIFY command.

use super::{Command, NotifyEvent, NotifyRequest, ParseError};

/// Parse `NOTIFY NONE` or `NOTIFY SET [STATUS] (<event-group> ...)`.
///
/// Only the `selected` mailbox specifier is fully supported: its requested
/// events are recorded. Other specifiers (`personal`, `subtree`, `mailboxes`,
/// …) are accepted and ignored per RFC 5465 §6 — a server may support a subset.
pub(super) fn parse_notify(tag: &str, args: &str) -> Result<Command, ParseError> {
	let bad = || ParseError::BadArguments(tag.to_string());
	let trimmed = args.trim();
	let (verb, rest) = match trimmed.split_once(char::is_whitespace) {
		Some((verb, rest)) => (verb, rest.trim()),
		None => (trimmed, ""),
	};
	if verb.eq_ignore_ascii_case("NONE") {
		if !rest.is_empty() {
			return Err(bad());
		}
		return Ok(Command::Notify(NotifyRequest::None));
	}
	if !verb.eq_ignore_ascii_case("SET") {
		return Err(bad());
	}
	// Optional STATUS return modifier between SET and the event-group list.
	let (status, rest) = match rest.split_once(char::is_whitespace) {
		Some((first, tail)) if first.eq_ignore_ascii_case("STATUS") => (true, tail.trim()),
		_ => (false, rest),
	};
	let selected = parse_event_groups(rest).ok_or_else(bad)?;
	Ok(Command::Notify(NotifyRequest::Set { status, selected }))
}

/// Parse a space-separated list of `(mailbox-specifier (events))` groups,
/// returning the events requested for the `selected` specifier. The list must
/// be non-empty and fully consumed.
fn parse_event_groups(input: &str) -> Option<Vec<NotifyEvent>> {
	let mut rest = input.trim();
	if rest.is_empty() {
		return None;
	}
	let mut selected = Vec::new();
	let mut saw_group = false;
	while !rest.is_empty() {
		let (specifier, events, tail) = parse_event_group(rest)?;
		saw_group = true;
		// `selected` and `selected-delayed` both scope to the selected mailbox.
		if specifier.eq_ignore_ascii_case("selected")
			|| specifier.eq_ignore_ascii_case("selected-delayed")
		{
			selected = events;
		}
		rest = tail.trim_start();
	}
	saw_group.then_some(selected)
}

/// Parse one `(mailbox-specifier (events))` group from the front of `input`,
/// returning the specifier, its events, and the unconsumed remainder.
fn parse_event_group(input: &str) -> Option<(&str, Vec<NotifyEvent>, &str)> {
	let inner_with_tail = input.trim_start().strip_prefix('(')?;
	let close = matching_paren(inner_with_tail)?;
	let inner = inner_with_tail[..close].trim();
	let tail = &inner_with_tail[close + 1..];

	// The specifier may carry its own parenthesised argument (subtree/mailboxes),
	// which we accept and skip; then an event list `(...)` or the keyword NONE.
	let (specifier, after) = inner.split_once(char::is_whitespace)?;
	let after = after.trim_start();
	// A `subtree`/`mailboxes` specifier is followed by a mailbox group, then the
	// events; skip the leading mailbox group if present.
	let after = if specifier.eq_ignore_ascii_case("subtree")
		|| specifier.eq_ignore_ascii_case("mailboxes")
	{
		match after.strip_prefix('(') {
			Some(rest) => {
				let mbox_close = matching_paren(rest)?;
				rest[mbox_close + 1..].trim_start()
			}
			None => return None,
		}
	} else {
		after
	};

	let events = parse_event_list(after)?;
	Some((specifier, events, tail))
}

/// Parse `(event event ...)` or the bare keyword `NONE` into an event set.
fn parse_event_list(input: &str) -> Option<Vec<NotifyEvent>> {
	let input = input.trim();
	if input.eq_ignore_ascii_case("NONE") {
		return Some(Vec::new());
	}
	let inner = input.strip_prefix('(')?.strip_suffix(')')?;
	let mut events = Vec::new();
	for word in inner.split_whitespace() {
		let event = match word.to_ascii_uppercase().as_str() {
			"MESSAGENEW" => NotifyEvent::MessageNew,
			"MESSAGEEXPUNGE" => NotifyEvent::MessageExpunge,
			"FLAGCHANGE" => NotifyEvent::FlagChange,
			"ANNOTATIONCHANGE" => NotifyEvent::AnnotationChange,
			// Unknown event names are rejected (RFC 5465 §6 BAD on bad syntax).
			_ => return None,
		};
		events.push(event);
	}
	Some(events)
}

/// Index of the `)` matching the implicit `(` already consumed at the front of
/// `input` (i.e. nesting depth starts at 1).
fn matching_paren(input: &str) -> Option<usize> {
	let mut depth = 1usize;
	for (index, byte) in input.bytes().enumerate() {
		match byte {
			b'(' => depth += 1,
			b')' => {
				depth -= 1;
				if depth == 0 {
					return Some(index);
				}
			}
			_ => {}
		}
	}
	None
}

#[cfg(test)]
#[path = "notify_tests.rs"]
mod tests;
