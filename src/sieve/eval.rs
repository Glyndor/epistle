//! Sieve test evaluation: `eval_test` and the per-test predicates (header,
//! address, envelope, body, size, date), the comparator, and glob matching.

use std::collections::HashMap;

use super::ast::{Argument, Test};
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

/// Match `value` against `key` with `comparator`; on a successful `:matches`,
/// store the wildcard captures as `${0..}` (RFC 5229 §6).
fn matches_capturing(
	comparator: Comparator,
	value: &str,
	key: &str,
	vars: &mut HashMap<String, String>,
) -> bool {
	if let Comparator::Matches = comparator {
		match glob_captures(&key.to_ascii_lowercase(), &value.to_ascii_lowercase()) {
			Some(captures) => {
				vars.insert("0".to_string(), value.to_string());
				for (index, capture) in captures.into_iter().enumerate() {
					vars.insert((index + 1).to_string(), capture);
				}
				true
			}
			None => false,
		}
	} else {
		comparator.matches(value, key)
	}
}

/// `date [comparator] <header-name> <date-part> <key-list>` (RFC 5260).
fn date_test(test: &Test, message: &Message) -> bool {
	let comparator = comparator(&test.args);
	let strings = strings(&test.args);
	if strings.len() < 3 {
		return false;
	}
	let (header, part, keys) = (&strings[0], &strings[1], &strings[2..]);
	for value in message.header_values(header) {
		if let Some(extracted) = super::date::extract_part(value, part)
			&& keys.iter().any(|key| comparator.matches(&extracted, key))
		{
			return true;
		}
	}
	false
}

/// `currentdate [comparator] <date-part> <key-list>` (RFC 5260).
fn currentdate_test(test: &Test, message: &Message) -> bool {
	let comparator = comparator(&test.args);
	let strings = strings(&test.args);
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
		.any(|key| comparator.matches(&extracted, key))
}

/// `header [comparator] <header-names> <key-list>`.
fn header_test(test: &Test, message: &Message, vars: &mut HashMap<String, String>) -> bool {
	let comparator = comparator(&test.args);
	let strings = strings(&test.args);
	let Some((names, keys)) = split_names_keys(&test.args, &strings) else {
		return false;
	};
	for name in &names {
		for value in message.header_values(name) {
			for key in &keys {
				if matches_capturing(comparator, value, key, vars) {
					return true;
				}
			}
		}
	}
	false
}

/// `address [comparator] [:all|:localpart|:domain] <header-names> <key-list>`.
fn address_test(test: &Test, message: &Message, vars: &mut HashMap<String, String>) -> bool {
	let comparator = comparator(&test.args);
	let Some((names, keys)) = split_names_keys(&test.args, &[]) else {
		return false;
	};
	let part = address_part(&test.args);
	for name in &names {
		for value in message.header_values(name) {
			let Some(addr) = part.of(&addr_spec(value)) else {
				continue;
			};
			for key in &keys {
				if matches_capturing(comparator, &addr, key, vars) {
					return true;
				}
			}
		}
	}
	false
}

/// `envelope [comparator] [part] <envelope-part-list> <key-list>` (RFC 5228
/// §5.4): `from` matches MAIL FROM, `to` matches RCPT TO.
fn envelope_test(test: &Test, message: &Message, vars: &mut HashMap<String, String>) -> bool {
	let comparator = comparator(&test.args);
	let Some((parts, keys)) = split_names_keys(&test.args, &[]) else {
		return false;
	};
	let part = address_part(&test.args);
	for which in &parts {
		let addresses: Vec<String> = match which.to_ascii_lowercase().as_str() {
			"from" => message.envelope_from.clone().into_iter().collect(),
			"to" => message.envelope_to.clone(),
			_ => Vec::new(),
		};
		for address in addresses {
			let Some(value) = part.of(&addr_spec(&address)) else {
				continue;
			};
			for key in &keys {
				if matches_capturing(comparator, &value, key, vars) {
					return true;
				}
			}
		}
	}
	false
}

/// The address-part selected by a tag, defaulting to the whole address.
fn address_part(args: &[Argument]) -> AddressPart {
	if has_tag(args, "localpart") {
		AddressPart::Local
	} else if has_tag(args, "domain") {
		AddressPart::Domain
	} else {
		AddressPart::All
	}
}

#[derive(Clone, Copy)]
enum AddressPart {
	All,
	Local,
	Domain,
}

impl AddressPart {
	/// Extract this part from an `addr-spec` (`local@domain`).
	fn of(self, addr: &str) -> Option<String> {
		match self {
			AddressPart::All => Some(addr.to_string()),
			AddressPart::Local => addr.rsplit_once('@').map(|(local, _)| local.to_string()),
			AddressPart::Domain => addr.rsplit_once('@').map(|(_, domain)| domain.to_string()),
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

/// `body [comparator] [:raw|:text] <key-list>` (RFC 5173): body text vs keys.
fn body_test(test: &Test, message: &Message, vars: &mut HashMap<String, String>) -> bool {
	let comparator = comparator(&test.args);
	strings(&test.args)
		.iter()
		.any(|key| matches_capturing(comparator, &message.body, key, vars))
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

/// Comparator selected by a tag, defaulting to `:is`.
#[derive(Clone, Copy)]
enum Comparator {
	Is,
	Contains,
	Matches,
}

impl Comparator {
	fn matches(self, value: &str, key: &str) -> bool {
		match self {
			Comparator::Is => value.eq_ignore_ascii_case(key),
			Comparator::Contains => value
				.to_ascii_lowercase()
				.contains(&key.to_ascii_lowercase()),
			Comparator::Matches => {
				glob_match(&key.to_ascii_lowercase(), &value.to_ascii_lowercase())
			}
		}
	}
}

fn comparator(args: &[Argument]) -> Comparator {
	if has_tag(args, "contains") {
		Comparator::Contains
	} else if has_tag(args, "matches") {
		Comparator::Matches
	} else {
		Comparator::Is
	}
}

/// Glob match supporting `*` (any run) and `?` (one char), per Sieve `:matches`.
fn glob_match(pattern: &str, text: &str) -> bool {
	let p: Vec<char> = pattern.chars().collect();
	let t: Vec<char> = text.chars().collect();
	let mut dp = vec![false; t.len() + 1];
	dp[0] = true;
	for &pc in &p {
		let mut prev = dp[0];
		dp[0] = dp[0] && pc == '*';
		for j in 0..t.len() {
			let here = dp[j + 1];
			dp[j + 1] = if pc == '*' {
				dp[j] || dp[j + 1]
			} else if pc == '?' || pc == t[j] {
				prev
			} else {
				false
			};
			prev = here;
		}
	}
	dp[t.len()]
}

/// Glob match returning the substrings captured by each `*`/`?` wildcard, in
/// order, or `None` if the pattern does not match. `*` is non-greedy (matches
/// the shortest run), giving the RFC 5229 leftmost capture assignment.
fn glob_captures(pattern: &str, text: &str) -> Option<Vec<String>> {
	let p: Vec<char> = pattern.chars().collect();
	let t: Vec<char> = text.chars().collect();
	let mut captures = Vec::new();
	capture_rec(&p, 0, &t, 0, &mut captures).then_some(captures)
}

fn capture_rec(p: &[char], pi: usize, t: &[char], ti: usize, caps: &mut Vec<String>) -> bool {
	if pi == p.len() {
		return ti == t.len();
	}
	match p[pi] {
		'*' => {
			// Try the shortest run first so earlier wildcards capture the least.
			for split in ti..=t.len() {
				caps.push(t[ti..split].iter().collect());
				if capture_rec(p, pi + 1, t, split, caps) {
					return true;
				}
				caps.pop();
			}
			false
		}
		'?' if ti < t.len() => {
			caps.push(t[ti].to_string());
			if capture_rec(p, pi + 1, t, ti + 1, caps) {
				return true;
			}
			caps.pop();
			false
		}
		c if ti < t.len() && t[ti] == c => capture_rec(p, pi + 1, t, ti + 1, caps),
		_ => false,
	}
}

/// Split the argument strings into (header-names, keys). The first string
/// argument or list is the names; everything after is keys.
fn split_names_keys(args: &[Argument], _all: &[String]) -> Option<(Vec<String>, Vec<String>)> {
	let mut groups: Vec<Vec<String>> = Vec::new();
	for arg in args {
		match arg {
			Argument::Str(s) => groups.push(vec![s.clone()]),
			Argument::StrList(list) => groups.push(list.clone()),
			_ => {}
		}
	}
	if groups.len() < 2 {
		return None;
	}
	let names = groups.remove(0);
	let keys = groups.into_iter().flatten().collect();
	Some((names, keys))
}
