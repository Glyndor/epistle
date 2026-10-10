//! LIST-EXTENDED selection and return options.

use super::parse::{parse_astring, parse_status_items};
use super::{Command, ListAttribute, ParseError, StatusItem};

pub(super) fn parse_list(tag: &str, args: &str) -> Result<Command, ParseError> {
	let bad = || ParseError::BadArguments(tag.to_string());
	let mut return_attributes = Vec::new();
	let mut select_subscribed = false;
	let args = args.trim_start();
	let args = if let Some(after) = args.strip_prefix('(') {
		let close = after.find(')').ok_or_else(bad)?;
		for option in after[..close].split_whitespace() {
			match option.to_ascii_uppercase().as_str() {
				"SUBSCRIBED" => {
					select_subscribed = true;
					return_attributes.push(ListAttribute::Subscribed);
				}
				"CHILDREN" => return_attributes.push(ListAttribute::Children),
				_ => return Err(bad()),
			}
		}
		after[close + 1..].trim_start()
	} else {
		args
	};
	let (reference, rest) = parse_astring(args).ok_or_else(bad)?;
	let (pattern, rest) = parse_astring(rest).ok_or_else(bad)?;
	let rest = rest.trim();
	let return_status = if rest.is_empty() {
		Vec::new()
	} else {
		let (status, attributes) = parse_return(rest).ok_or_else(bad)?;
		return_attributes.extend(attributes);
		status
	};
	Ok(Command::List {
		reference,
		pattern,
		return_status,
		select_subscribed,
		return_attributes,
	})
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
