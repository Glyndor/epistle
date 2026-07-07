//! Sieve test evaluation: `eval_test` and the per-test predicates (header,
//! address, envelope, body, size, date), the comparator, and glob matching.

use std::collections::HashMap;

use super::ast::{Argument, Test};
use super::compare::{self, MatchSpec};
use super::interp::{has_tag, strings};
use super::message::Message;

pub(super) fn eval_test(
	test: &Test,
	message: &Message,
	vars: &mut HashMap<String, String>,
) -> bool {
	match test.name.as_str() {
		"true" => true,
		"false" => false,
		"not" => !test
			.children
			.first()
			.is_some_and(|c| eval_test(c, message, vars)),
		"allof" => test.children.iter().all(|c| eval_test(c, message, vars)),
		"anyof" => test.children.iter().any(|c| eval_test(c, message, vars)),
		"exists" => strings(&test.args)
			.iter()
			.all(|name| !message.header_values(name).is_empty()),
		"header" => header_test(test, message, vars),
		"address" => address_test(test, message, vars),
		"envelope" => envelope_test(test, message, vars),
		"body" => body_test(test, message, vars),
		"size" => size_test(test, message),
		"date" => date_test(test, message),
		"currentdate" => currentdate_test(test, message),
		// Unknown test: fail safe.
		_ => false,
	}
}

/// `date [match-type] [comparator] <header-name> <date-part> <key-list>`
/// (RFC 5260).
fn date_test(test: &Test, message: &Message) -> bool {
	let spec = compare::match_spec(&test.args);
	let strings = compare::positional_strings(&test.args);
	if strings.len() < 3 {
		return false;
	}
	let (header, part, keys) = (&strings[0], &strings[1], &strings[2..]);
	for value in message.header_values(header) {
		if let Some(extracted) = super::date::extract_part(value, part)
			&& keys.iter().any(|key| spec.test_simple(&extracted, key))
		{
			return true;
		}
	}
	false
}

/// `currentdate [match-type] [comparator] <date-part> <key-list>` (RFC 5260).
fn currentdate_test(test: &Test, message: &Message) -> bool {
	let spec = compare::match_spec(&test.args);
	let strings = compare::positional_strings(&test.args);
	if strings.len() < 2 {
		return false;
	}
	let now = message.now.unwrap_or_else(|| {
		std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.map(|d| d.as_secs())
			.unwrap_or(0)
	});
	let Some(extracted) = super::date::extract_part_from_unix(now, &strings[0]) else {
		return false;
	};
	strings[1..]
		.iter()
		.any(|key| spec.test_simple(&extracted, key))
}

/// `header [match-type] [comparator] <header-names> <key-list>`.
fn header_test(test: &Test, message: &Message, vars: &mut HashMap<String, String>) -> bool {
	let spec = compare::match_spec(&test.args);
	let Some((names, keys)) = split_names_keys(&test.args) else {
		return false;
	};
	let values = || names.iter().flat_map(|name| message.header_values(name));
	if let Some(rel) = spec.count_rel() {
		let count = values().count();
		return keys.iter().any(|key| spec.count_matches(rel, count, key));
	}
	for value in values() {
		for key in &keys {
			if spec.test(value, key, vars) {
				return true;
			}
		}
	}
	false
}

/// `address [match-type] [comparator] [part] <header-names> <key-list>`.
fn address_test(test: &Test, message: &Message, vars: &mut HashMap<String, String>) -> bool {
	let spec = compare::match_spec(&test.args);
	let Some((names, keys)) = split_names_keys(&test.args) else {
		return false;
	};
	let part = address_part(&test.args);
	let extracted: Vec<String> = names
		.iter()
		.flat_map(|name| message.header_values(name))
		.filter_map(|value| part.of(&addr_spec(value)))
		.collect();
	match_values(&spec, &extracted, &keys, vars)
}

/// `envelope [match-type] [comparator] [part] <envelope-part-list> <key-list>`
/// (RFC 5228 §5.4): `from` matches MAIL FROM, `to` matches RCPT TO.
fn envelope_test(test: &Test, message: &Message, vars: &mut HashMap<String, String>) -> bool {
	let spec = compare::match_spec(&test.args);
	let Some((parts, keys)) = split_names_keys(&test.args) else {
		return false;
	};
	let part = address_part(&test.args);
	let extracted: Vec<String> = parts
		.iter()
		.flat_map(|which| match which.to_ascii_lowercase().as_str() {
			"from" => message.envelope_from.clone().into_iter().collect(),
			"to" => message.envelope_to.clone(),
			_ => Vec::new(),
		})
		.filter_map(|address| part.of(&addr_spec(&address)))
		.collect();
	match_values(&spec, &extracted, &keys, vars)
}

/// Test extracted values against keys, honoring `:count`.
fn match_values(
	spec: &MatchSpec,
	values: &[String],
	keys: &[String],
	vars: &mut HashMap<String, String>,
) -> bool {
	if let Some(rel) = spec.count_rel() {
		return keys
			.iter()
			.any(|key| spec.count_matches(rel, values.len(), key));
	}
	for value in values {
		for key in keys {
			if spec.test(value, key, vars) {
				return true;
			}
		}
	}
	false
}

/// The subaddress separator (RFC 5233). `user+detail@domain`: `+` splits the
/// local-part into the `:user` and `:detail` sub-parts.
const SUBADDRESS_SEPARATOR: char = '+';

/// The address-part selected by a tag, defaulting to the whole address.
/// `:user`/`:detail` are the subaddress parts (RFC 5233).
fn address_part(args: &[Argument]) -> AddressPart {
	if has_tag(args, "localpart") {
		AddressPart::Local
	} else if has_tag(args, "domain") {
		AddressPart::Domain
	} else if has_tag(args, "user") {
		AddressPart::User
	} else if has_tag(args, "detail") {
		AddressPart::Detail
	} else {
		AddressPart::All
	}
}

#[derive(Clone, Copy)]
enum AddressPart {
	All,
	Local,
	Domain,
	/// Local-part before the first separator (RFC 5233 `:user`).
	User,
	/// Local-part after the first separator (RFC 5233 `:detail`).
	Detail,
}

impl AddressPart {
	/// Extract this part from an `addr-spec` (`local@domain`). For `:detail`,
	/// `None` means the address has no detail sub-part, so no key can match.
	fn of(self, addr: &str) -> Option<String> {
		let local = || addr.rsplit_once('@').map_or(addr, |(local, _)| local);
		match self {
			AddressPart::All => Some(addr.to_string()),
			AddressPart::Local => addr.rsplit_once('@').map(|(local, _)| local.to_string()),
			AddressPart::Domain => addr.rsplit_once('@').map(|(_, domain)| domain.to_string()),
			AddressPart::User => Some(
				local()
					.split_once(SUBADDRESS_SEPARATOR)
					.map_or_else(|| local().to_string(), |(user, _)| user.to_string()),
			),
			AddressPart::Detail => local()
				.split_once(SUBADDRESS_SEPARATOR)
				.map(|(_, detail)| detail.to_string()),
		}
	}
}

/// The bare `addr-spec` from a header value (the last angle-addr, else trimmed).
fn addr_spec(value: &str) -> String {
	if let Some(open) = value.rfind('<')
		&& let Some(close) = value[open..].find('>')
	{
		return value[open + 1..open + close].trim().to_string();
	}
	value.trim().to_string()
}

/// `body [match-type] [comparator] [:raw|:text] <key-list>` (RFC 5173).
fn body_test(test: &Test, message: &Message, vars: &mut HashMap<String, String>) -> bool {
	let spec = compare::match_spec(&test.args);
	compare::positional_strings(&test.args)
		.iter()
		.any(|key| spec.test(&message.body, key, vars))
}

/// `size :over|:under <number>`.
fn size_test(test: &Test, message: &Message) -> bool {
	let limit = test.args.iter().find_map(|arg| match arg {
		Argument::Number(n) => Some(*n as usize),
		_ => None,
	});
	let Some(limit) = limit else { return false };
	if has_tag(&test.args, "over") {
		message.size > limit
	} else if has_tag(&test.args, "under") {
		message.size < limit
	} else {
		false
	}
}

/// Split the positional arguments into (header-names, keys). The first string
/// or list is the names; everything after is keys. Strings consumed by
/// `:comparator`/`:value`/`:count` are excluded.
fn split_names_keys(args: &[Argument]) -> Option<(Vec<String>, Vec<String>)> {
	let mut groups = compare::positional_groups(args);
	if groups.len() < 2 {
		return None;
	}
	let names = groups.remove(0);
	let keys = groups.into_iter().flatten().collect();
	Some((names, keys))
}
