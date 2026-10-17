//! Sieve test evaluation: `eval_test` and the per-test predicates (header,
//! address, envelope, body, size, date), the comparator, and glob matching.

use super::ast::{Argument, Test};
use super::compare::{self, MatchSpec};
use super::env::Env;
use super::interp::{has_tag, strings};
use super::message::Message;

/// What looking up a header by name costs a run: the name, and a minimum.
fn lookup_cost(name: &str) -> u64 {
	64 + name.len() as u64
}

pub(super) fn eval_test(test: &Test, message: &Message, vars: &mut Env) -> bool {
	if !vars.step() {
		return false;
	}
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
			.all(|name| vars.charge(lookup_cost(name)) && message.header_count(name) > 0),
		"header" => header_test(test, message, vars),
		"address" => address_test(test, message, vars),
		"envelope" => envelope_test(test, message, vars),
		"body" => body_test(test, message, vars),
		"size" => size_test(test, message),
		"date" => date_test(test, message, vars),
		"currentdate" => currentdate_test(test, message, vars),
		"mailboxexists" => mailboxexists_test(test, message),
		// Unknown test: fail safe.
		_ => false,
	}
}

/// `mailboxexists <mailbox-names>` (RFC 5490 §3.1): true when every named
/// mailbox exists for the recipient account and the account may deliver
/// into it. Names go through the same modified UTF-7 encoding `fileinto`
/// uses (the names IMAP stores on disk). A mailbox set the caller did
/// not attach leaves the test false, so a script without context is
/// fail-safe and never matches by accident.
fn mailboxexists_test(test: &Test, message: &Message) -> bool {
	let names = compare::positional_strings(&test.args);
	let Some(mailboxes) = &message.mailboxes else {
		return false;
	};
	names.iter().all(|name| mailbox_exists(name, mailboxes))
}

/// Whether the given Sieve name maps to an existing mailbox in `mailboxes`.
/// INBOX is always present for a valid account, regardless of the supplied
/// list, so a script can rely on it. Other names are looked up under their
/// IMAP on-disk spelling (modified UTF-7).
fn mailbox_exists(name: &str, mailboxes: &[String]) -> bool {
	if name.eq_ignore_ascii_case("INBOX") {
		return true;
	}
	mailboxes.contains(&crate::util::mutf7::encode(name))
}

/// `date [match-type] [comparator] <header-name> <date-part> <key-list>`
/// (RFC 5260).
fn date_test(test: &Test, message: &Message, vars: &mut Env) -> bool {
	let spec = compare::match_spec(&test.args);
	let strings = compare::positional_strings(&test.args);
	if strings.len() < 3 {
		return false;
	}
	let (header, part, keys) = (&strings[0], &strings[1], &strings[2..]);
	if !vars.charge(lookup_cost(header)) {
		return false;
	}
	for value in message.header_values(header) {
		// The value is read to find its date part, and every key is
		// compared with it: all of that is paid for.
		if !vars.charge(value.len() as u64) {
			return false;
		}
		if let Some(extracted) = super::date::extract_part(value, part)
			&& keys.iter().any(|key| spec.test(&extracted, key, vars))
		{
			return true;
		}
	}
	false
}

/// `currentdate [match-type] [comparator] <date-part> <key-list>` (RFC 5260).
fn currentdate_test(test: &Test, message: &Message, vars: &mut Env) -> bool {
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
		.any(|key| spec.test(&extracted, key, vars))
}

/// `header [match-type] [comparator] <header-names> <key-list>`.
fn header_test(test: &Test, message: &Message, vars: &mut Env) -> bool {
	let spec = compare::match_spec(&test.args);
	let Some((names, keys)) = split_names_keys(&test.args) else {
		return false;
	};
	// Looking a name up costs the name; what is found is paid for as it is
	// visited, in `spec.test`.
	if !names.iter().all(|name| vars.charge(lookup_cost(name))) {
		return false;
	}
	if let Some(rel) = spec.count_rel() {
		let count: usize = names.iter().map(|name| message.header_count(name)).sum();
		return keys.iter().any(|key| spec.count_matches(rel, count, key));
	}
	for value in names.iter().flat_map(|name| message.header_values(name)) {
		for key in &keys {
			if spec.test(value, key, vars) {
				return true;
			}
		}
	}
	false
}

/// `address [match-type] [comparator] [part] <header-names> <key-list>`.
fn address_test(test: &Test, message: &Message, vars: &mut Env) -> bool {
	let spec = compare::match_spec(&test.args);
	let Some((names, keys)) = split_names_keys(&test.args) else {
		return false;
	};
	let part = address_part(&test.args);
	if !names.iter().all(|name| vars.charge(lookup_cost(name))) {
		return false;
	}
	let mut extracted: Vec<String> = Vec::new();
	for value in names.iter().flat_map(|name| message.header_values(name)) {
		// What is copied out of the message is paid for first.
		if !vars.charge(value.len() as u64) {
			return false;
		}
		extracted.extend(part.of(&addr_spec(value)));
	}
	match_values(&spec, &extracted, &keys, vars)
}

/// `envelope [match-type] [comparator] [part] <envelope-part-list> <key-list>`
/// (RFC 5228 §5.4): `from` matches MAIL FROM, `to` matches RCPT TO.
fn envelope_test(test: &Test, message: &Message, vars: &mut Env) -> bool {
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
fn match_values(spec: &MatchSpec, values: &[String], keys: &[String], vars: &mut Env) -> bool {
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
fn body_test(test: &Test, message: &Message, vars: &mut Env) -> bool {
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
