//! Parsing for the RFC 5465 NOTIFY command.

use super::parse::parse_astring;
use super::{Command, NotifyEvent, NotifyGroup, NotifyMailboxes, NotifyRequest, ParseError};

/// Parse `NOTIFY NONE` or `NOTIFY SET [STATUS] (<event-group> ...)`.
///
/// The events of the `selected` specifier are pushed while a mailbox is
/// selected. The groups for other mailboxes (`inboxes`, `personal`,
/// `subscribed`, `subtree`, `mailboxes`) are kept so `SET STATUS` can report
/// them; an unknown specifier is accepted and ignored, as before.
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
	let (selected, others) = parse_event_groups(rest).ok_or_else(bad)?;
	Ok(Command::Notify(NotifyRequest::Set {
		status,
		selected,
		others,
	}))
}

/// Parse a space-separated list of `(mailbox-specifier (events))` groups into
/// the events of the `selected` specifier and the groups for other mailboxes.
/// The list must be non-empty and fully consumed.
fn parse_event_groups(input: &str) -> Option<(Vec<NotifyEvent>, Vec<NotifyGroup>)> {
	let mut rest = input.trim();
	if rest.is_empty() {
		return None;
	}
	let mut selected = Vec::new();
	let mut others = Vec::new();
	while !rest.is_empty() {
		let (specifier, mailboxes, events, tail) = parse_event_group(rest)?;
		// `selected` and `selected-delayed` both scope to the selected mailbox.
		if specifier.eq_ignore_ascii_case("selected")
			|| specifier.eq_ignore_ascii_case("selected-delayed")
		{
			selected = events;
		} else if let Some(mailboxes) = mailboxes {
			others.push(NotifyGroup { mailboxes, events });
		}
		rest = tail.trim_start();
	}
	Some((selected, others))
}

type EventGroup<'a> = (&'a str, Option<NotifyMailboxes>, Vec<NotifyEvent>, &'a str);

/// Parse one `(mailbox-specifier (events))` group from the front of `input`,
/// returning the specifier, the mailboxes it names, its events, and the
/// unconsumed remainder.
fn parse_event_group(input: &str) -> Option<EventGroup<'_>> {
	let inner_with_tail = input.trim_start().strip_prefix('(')?;
	let close = matching_paren(inner_with_tail)?;
	let inner = inner_with_tail[..close].trim();
	let tail = &inner_with_tail[close + 1..];

	let (specifier, after) = inner.split_once(char::is_whitespace)?;
	let after = after.trim_start();
	let (mailboxes, after) = match specifier.to_ascii_lowercase().as_str() {
		"inboxes" => (Some(NotifyMailboxes::Inboxes), after),
		"personal" => (Some(NotifyMailboxes::Personal), after),
		"subscribed" => (Some(NotifyMailboxes::Subscribed), after),
		"subtree" => {
			let (names, after) = one_or_more_mailbox(after)?;
			(Some(NotifyMailboxes::Subtree(names)), after)
		}
		"mailboxes" => {
			let (names, after) = one_or_more_mailbox(after)?;
			(Some(NotifyMailboxes::Mailboxes(names)), after)
		}
		_ => (None, after),
	};

	let events = parse_event_list(after)?;
	Some((specifier, mailboxes, events, tail))
}

/// `one-or-more-mailbox = mailbox / "(" mailbox *(SP mailbox) ")"`
/// (RFC 5465 §8), returning the names and the remainder.
fn one_or_more_mailbox(input: &str) -> Option<(Vec<String>, &str)> {
	let Some(mut rest) = input.strip_prefix('(') else {
		let (name, rest) = mailbox_name(input)?;
		return Some((vec![name], rest.trim_start()));
	};
	let mut names = Vec::new();
	loop {
		rest = rest.trim_start();
		if let Some(after) = rest.strip_prefix(')') {
			return (!names.is_empty()).then(|| (names, after.trim_start()));
		}
		let (name, after) = mailbox_name(rest)?;
		names.push(name);
		rest = after;
	}
}

/// One non-empty mailbox name: a quoted string, or an atom that ends at a
/// space or a parenthesis.
fn mailbox_name(input: &str) -> Option<(String, &str)> {
	let input = input.trim_start();
	if input.starts_with('"') {
		return parse_astring(input).filter(|(name, _)| !name.is_empty());
	}
	let end = input
		.find(|c: char| c == ' ' || c == '(' || c == ')')
		.unwrap_or(input.len());
	(end > 0).then(|| (input[..end].to_string(), &input[end..]))
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
