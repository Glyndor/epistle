//! LIST and its LIST-EXTENDED selection options, patterns and return options
//! (RFC 9051 §6.3.9, RFC 5258).

use super::parse::{parse_astring, parse_status_items};
use super::{Command, ListAttribute, ParseError, StatusItem};

/// A parsed `LIST`, plain or extended.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListCommand {
	/// Reference name (often `""`); prepended to every pattern.
	pub reference: String,
	/// One or more patterns (`%` for one level, `*` for any); a name is
	/// listed when it matches any of them (RFC 5258 §3).
	pub patterns: Vec<String>,
	/// `RETURN (STATUS (...))` items to report inline (LIST-STATUS, RFC 5819).
	pub return_status: Vec<StatusItem>,
	/// `(SUBSCRIBED)` selection: list only subscribed names (RFC 5258).
	pub select_subscribed: bool,
	/// `(SPECIAL-USE)` selection: list only mailboxes with a role (RFC 6154).
	pub select_special_use: bool,
	/// `(RECURSIVEMATCH)`: also list a parent whose descendant meets the
	/// selection but does not match, with `CHILDINFO` (RFC 5258 §3.5).
	pub recursive_match: bool,
	/// The extended syntax was used (selection options, a pattern list or
	/// return options), so the reply follows RFC 5258: a name that does not
	/// exist carries `\NonExistent`.
	pub extended: bool,
	/// Mailbox attributes explicitly requested by selection or RETURN.
	pub return_attributes: Vec<ListAttribute>,
}

pub(super) fn parse_list(tag: &str, args: &str) -> Result<Command, ParseError> {
	let bad = || ParseError::BadArguments(tag.to_string());
	let mut list = ListCommand::default();
	let args = args.trim_start();
	let args = if let Some(after) = args.strip_prefix('(') {
		list.extended = true;
		let close = after.find(')').ok_or_else(bad)?;
		for option in after[..close].split_whitespace() {
			match option.to_ascii_uppercase().as_str() {
				"SUBSCRIBED" => {
					list.select_subscribed = true;
					list.return_attributes.push(ListAttribute::Subscribed);
				}
				"CHILDREN" => list.return_attributes.push(ListAttribute::Children),
				"SPECIAL-USE" => {
					list.select_special_use = true;
					list.return_attributes.push(ListAttribute::SpecialUse);
				}
				// Every mailbox is local, so REMOTE selects nothing more.
				"REMOTE" => {}
				"RECURSIVEMATCH" => list.recursive_match = true,
				_ => return Err(bad()),
			}
		}
		after[close + 1..].trim_start()
	} else {
		args
	};
	// RECURSIVEMATCH alone, or with only REMOTE, is a syntax error (RFC 5258
	// §3).
	if list.recursive_match && !list.select_subscribed && !list.select_special_use {
		return Err(bad());
	}
	let (reference, rest) = parse_astring(args).ok_or_else(bad)?;
	list.reference = reference;
	let rest = rest.trim_start();
	let rest = if let Some(inner) = rest.strip_prefix('(') {
		list.extended = true;
		let (patterns, rest) = parse_patterns(inner).ok_or_else(bad)?;
		list.patterns = patterns;
		rest
	} else {
		let (pattern, rest) = parse_astring(rest).ok_or_else(bad)?;
		list.patterns.push(pattern);
		rest
	};
	let rest = rest.trim();
	if !rest.is_empty() {
		list.extended = true;
		let (status, attributes) = parse_return(rest).ok_or_else(bad)?;
		list.return_status = status;
		list.return_attributes.extend(attributes);
	}
	Ok(Command::List(list))
}

/// The patterns of a parenthesized list, up to and past its `)`. An atom ends
/// at a space or the closing parenthesis; an empty list is refused.
fn parse_patterns(mut rest: &str) -> Option<(Vec<String>, &str)> {
	let mut patterns = Vec::new();
	loop {
		rest = rest.trim_start();
		if let Some(after) = rest.strip_prefix(')') {
			return (!patterns.is_empty()).then_some((patterns, after));
		}
		if rest.starts_with('"') {
			let (pattern, after) = parse_astring(rest)?;
			patterns.push(pattern);
			rest = after;
		} else {
			let end = rest.find([' ', ')']).unwrap_or(rest.len());
			if end == 0 {
				return None;
			}
			patterns.push(rest[..end].to_string());
			rest = &rest[end..];
		}
	}
}

fn parse_return(rest: &str) -> Option<(Vec<StatusItem>, Vec<ListAttribute>)> {
	let (verb, group) = rest.split_once(char::is_whitespace)?;
	if !verb.eq_ignore_ascii_case("RETURN") {
		return None;
	}
	let mut rest = group.trim().strip_prefix('(')?.strip_suffix(')')?.trim();
	let mut status = Vec::new();
	let mut attributes = Vec::new();
	while !rest.is_empty() {
		let (word, after) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
		if word.eq_ignore_ascii_case("STATUS") {
			if !status.is_empty() {
				return None;
			}
			let inner = after.trim_start().strip_prefix('(')?;
			let close = inner.find(')')?;
			status = parse_status_items(&inner[..close])?;
			rest = inner[close + 1..].trim_start();
		} else {
			attributes.push(match word.to_ascii_uppercase().as_str() {
				"SUBSCRIBED" => ListAttribute::Subscribed,
				"CHILDREN" => ListAttribute::Children,
				"SPECIAL-USE" => ListAttribute::SpecialUse,
				_ => return None,
			});
			rest = after.trim_start();
		}
	}
	Some((status, attributes))
}
