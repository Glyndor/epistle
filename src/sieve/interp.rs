//! Sieve interpreter (RFC 5228 §2.10, §5): evaluate a script against a message
//! to decide where it is delivered.
//!
//! Supported tests: `true`/`false`, `exists`, `header`, `size`, and the
//! `allof`/`anyof`/`not` combinators with the `:is`/`:contains`/`:matches`
//! comparators. Supported actions: `keep`, `discard`, `fileinto`, `redirect`,
//! `stop` (and `require`, which is a no-op at run time). Unknown tests evaluate
//! to false and unknown actions are ignored, so an unsupported script fails
//! safe rather than misdelivering.

use super::ast::{Argument, Command, Test};

/// The delivery decision a script produces.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Outcome {
	/// Deliver to the inbox (explicit or implicit keep).
	pub keep: bool,
	/// Mailboxes to file into.
	pub fileinto: Vec<String>,
	/// Addresses to redirect to.
	pub redirects: Vec<String>,
	/// The message was explicitly discarded.
	pub discarded: bool,
}

/// A message as the interpreter sees it: parsed headers and total size.
pub struct Message {
	headers: Vec<(String, String)>,
	size: usize,
}

impl Message {
	/// Parse headers (unfolded) and record the total size.
	pub fn parse(raw: &[u8]) -> Message {
		let header_end = raw
			.windows(4)
			.position(|w| w == b"\r\n\r\n")
			.map(|p| p + 2)
			.unwrap_or(raw.len());
		let block = String::from_utf8_lossy(&raw[..header_end]);
		let mut headers = Vec::new();
		let mut current: Option<String> = None;
		for line in block.split_inclusive('\n') {
			let content = line.trim_end_matches(['\r', '\n']);
			if content.starts_with(' ') || content.starts_with('\t') {
				if let Some(buffer) = &mut current {
					buffer.push(' ');
					buffer.push_str(content.trim_start());
				}
				continue;
			}
			if let Some(buffer) = current.take() {
				push_header(&mut headers, &buffer);
			}
			if !content.is_empty() {
				current = Some(content.to_string());
			}
		}
		if let Some(buffer) = current.take() {
			push_header(&mut headers, &buffer);
		}
		Message {
			headers,
			size: raw.len(),
		}
	}

	fn header_values(&self, name: &str) -> Vec<&str> {
		self.headers
			.iter()
			.filter(|(header, _)| header.eq_ignore_ascii_case(name))
			.map(|(_, value)| value.as_str())
			.collect()
	}
}

fn push_header(headers: &mut Vec<(String, String)>, line: &str) {
	if let Some(colon) = line.find(':') {
		headers.push((
			line[..colon].trim_end().to_string(),
			line[colon + 1..].trim().to_string(),
		));
	}
}

/// Run a parsed script against a message and return the delivery outcome.
pub fn evaluate(script: &[Command], message: &Message) -> Outcome {
	let mut outcome = Outcome::default();
	let mut cancel_implicit = false;
	run(script, message, &mut outcome, &mut cancel_implicit);
	// Implicit keep applies unless an action cancelled it.
	if !cancel_implicit {
		outcome.keep = true;
	}
	outcome
}

/// Returns true if a `stop` was executed (halts further commands).
fn run(
	commands: &[Command],
	message: &Message,
	outcome: &mut Outcome,
	cancel_implicit: &mut bool,
) -> bool {
	for command in commands {
		match command {
			Command::Action { name, args } => match name.as_str() {
				"keep" => outcome.keep = true,
				"discard" => {
					outcome.discarded = true;
					*cancel_implicit = true;
				}
				"fileinto" => {
					if let Some(target) = first_str(args) {
						outcome.fileinto.push(target);
						*cancel_implicit = true;
					}
				}
				"redirect" => {
					if let Some(target) = first_str(args) {
						outcome.redirects.push(target);
						*cancel_implicit = true;
					}
				}
				"stop" => return true,
				// `require` and any unsupported action: no-op.
				_ => {}
			},
			Command::If(conditional) => {
				let mut taken = false;
				for branch in &conditional.branches {
					if eval_test(&branch.test, message) {
						if run(&branch.body, message, outcome, cancel_implicit) {
							return true;
						}
						taken = true;
						break;
					}
				}
				if !taken
					&& let Some(body) = &conditional.otherwise
					&& run(body, message, outcome, cancel_implicit)
				{
					return true;
				}
			}
		}
	}
	false
}

fn eval_test(test: &Test, message: &Message) -> bool {
	match test.name.as_str() {
		"true" => true,
		"false" => false,
		"not" => !test.children.first().is_some_and(|c| eval_test(c, message)),
		"allof" => test.children.iter().all(|c| eval_test(c, message)),
		"anyof" => test.children.iter().any(|c| eval_test(c, message)),
		"exists" => strings(&test.args)
			.iter()
			.all(|name| !message.header_values(name).is_empty()),
		"header" => header_test(test, message),
		"address" => address_test(test, message),
		"size" => size_test(test, message),
		// Unknown test: fail safe.
		_ => false,
	}
}

/// `header [comparator] <header-names> <key-list>`.
fn header_test(test: &Test, message: &Message) -> bool {
	let comparator = comparator(&test.args);
	let strings = strings(&test.args);
	// The first string-group is header names, the rest are keys. With a single
	// string each, the split is names=[first], keys=[rest].
	let Some((names, keys)) = split_names_keys(&test.args, &strings) else {
		return false;
	};
	for name in &names {
		for value in message.header_values(name) {
			for key in &keys {
				if comparator.matches(value, key) {
					return true;
				}
			}
		}
	}
	false
}

/// `address [comparator] [:all|:localpart|:domain] <header-names> <key-list>`.
/// Compares the chosen part of the addresses in the named headers, per
/// RFC 5228 §5.1. Defaults to the whole address (`:all`).
fn address_test(test: &Test, message: &Message) -> bool {
	let comparator = comparator(&test.args);
	let Some((names, keys)) = split_names_keys(&test.args, &[]) else {
		return false;
	};
	let part = if has_tag(&test.args, "localpart") {
		AddressPart::Local
	} else if has_tag(&test.args, "domain") {
		AddressPart::Domain
	} else {
		AddressPart::All
	};
	for name in &names {
		for value in message.header_values(name) {
			let Some(addr) = part.of(&addr_spec(value)) else {
				continue;
			};
			for key in &keys {
				if comparator.matches(&addr, key) {
					return true;
				}
			}
		}
	}
	false
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

/// The bare `addr-spec` from a header value: the contents of the last
/// angle-addr (`Name <a@b>`), or the trimmed value if there is none.
fn addr_spec(value: &str) -> String {
	if let Some(open) = value.rfind('<')
		&& let Some(close) = value[open..].find('>')
	{
		return value[open + 1..open + close].trim().to_string();
	}
	value.trim().to_string()
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
	// Classic dynamic-programming wildcard match.
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

fn first_str(args: &[Argument]) -> Option<String> {
	args.iter().find_map(|arg| match arg {
		Argument::Str(s) => Some(s.clone()),
		_ => None,
	})
}

/// All bare strings from arguments, flattening string lists, in order.
fn strings(args: &[Argument]) -> Vec<String> {
	let mut out = Vec::new();
	for arg in args {
		match arg {
			Argument::Str(s) => out.push(s.clone()),
			Argument::StrList(list) => out.extend(list.iter().cloned()),
			_ => {}
		}
	}
	out
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

fn has_tag(args: &[Argument], tag: &str) -> bool {
	args.iter()
		.any(|arg| matches!(arg, Argument::Tag(t) if t == tag))
}
