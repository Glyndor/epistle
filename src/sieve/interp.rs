//! Sieve interpreter (RFC 5228 §2.10, §5): evaluate a script against a message
//! to decide where it is delivered. Unknown tests evaluate to false and unknown
//! actions are ignored, so an unsupported script fails safe.

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
	/// IMAP flags set on the delivered message (imap4flags, RFC 5232).
	pub flags: Vec<String>,
	/// The message was rejected (reject/ereject, RFC 5429): the reason is
	/// bounced to the sender and the message is not delivered.
	pub reject: Option<String>,
	/// A `vacation` autoresponse to send in addition to normal delivery
	/// (RFC 5230), subject to the caller's suppression and dedup rules.
	pub vacation: Option<VacationRequest>,
}

/// A parsed `vacation` action (RFC 5230). The caller decides whether to send.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VacationRequest {
	/// The reply body (`:reason`, the positional argument).
	pub reason: String,
	/// An explicit `:subject`, else derived from the original.
	pub subject: Option<String>,
	/// An explicit `:from`, else the responding user's address.
	pub from: Option<String>,
	/// At most one reply per sender per this many days (`:days`, default 7).
	pub days: u64,
}

pub use super::message::Message;

/// Run a parsed script against a message and return the delivery outcome.
pub fn evaluate(script: &[Command], message: &Message) -> Outcome {
	let mut outcome = Outcome::default();
	let mut cancel_implicit = false;
	let mut vars = std::collections::HashMap::new();
	run(
		script,
		message,
		&mut outcome,
		&mut cancel_implicit,
		&mut vars,
	);
	// Implicit keep applies unless an action cancelled it.
	if !cancel_implicit {
		outcome.keep = true;
	}
	outcome
}

use super::vars::expand;

/// Returns true if a `stop` was executed (halts further commands).
fn run(
	commands: &[Command],
	message: &Message,
	outcome: &mut Outcome,
	cancel_implicit: &mut bool,
	vars: &mut std::collections::HashMap<String, String>,
) -> bool {
	for command in commands {
		match command {
			Command::Action { name, args } => match name.as_str() {
				"keep" => outcome.keep = true,
				"discard" => {
					outcome.discarded = true;
					*cancel_implicit = true;
				}
				// reject / ereject (RFC 5429): refuse + bounce; cancels keep.
				"reject" | "ereject" => {
					if let Some(reason) = first_str(args) {
						outcome.reject = Some(expand(&reason, vars));
						*cancel_implicit = true;
					}
				}
				// set (RFC 5229): store a variable for later `${name}` expansion.
				"set" => {
					let strings = strings(args);
					if let [name, value, ..] = strings.as_slice() {
						let value = expand(value, vars);
						vars.insert(name.clone(), value);
					}
				}
				// vacation (RFC 5230): autoresponse alongside normal delivery
				// (does not cancel the implicit keep).
				"vacation" => outcome.vacation = parse_vacation(args),
				"fileinto" => {
					if let Some(target) = first_str(args) {
						outcome.fileinto.push(expand(&target, vars));
						// `:copy` (RFC 3894) leaves the implicit keep in place.
						if !has_tag(args, "copy") {
							*cancel_implicit = true;
						}
					}
				}
				"redirect" => {
					if let Some(target) = first_str(args) {
						outcome.redirects.push(expand(&target, vars));
						if !has_tag(args, "copy") {
							*cancel_implicit = true;
						}
					}
				}
				"stop" => return true,
				// imap4flags (RFC 5232): set/add/remove IMAP flags for delivery.
				"setflag" => outcome.flags = flag_list(args),
				"addflag" => {
					for flag in flag_list(args) {
						if !outcome.flags.contains(&flag) {
							outcome.flags.push(flag);
						}
					}
				}
				"removeflag" => {
					let remove = flag_list(args);
					outcome.flags.retain(|flag| !remove.contains(flag));
				}
				// `require` and any unsupported action: no-op.
				_ => {}
			},
			Command::If(conditional) => {
				let mut taken = false;
				for branch in &conditional.branches {
					if eval_test(&branch.test, message) {
						if run(&branch.body, message, outcome, cancel_implicit, vars) {
							return true;
						}
						taken = true;
						break;
					}
				}
				if !taken
					&& let Some(body) = &conditional.otherwise
					&& run(body, message, outcome, cancel_implicit, vars)
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
		"envelope" => envelope_test(test, message),
		"body" => body_test(test, message),
		"size" => size_test(test, message),
		"date" => date_test(test, message),
		"currentdate" => currentdate_test(test, message),
		// Unknown test: fail safe.
		_ => false,
	}
}

/// Parse a `vacation` action's arguments (RFC 5230): the tagged `:days`,
/// `:subject`, `:from` (others ignored) and the positional reason string.
fn parse_vacation(args: &[Argument]) -> Option<VacationRequest> {
	let mut request = VacationRequest {
		days: 7,
		..VacationRequest::default()
	};
	let mut reason = None;
	let mut iter = args.iter();
	while let Some(arg) = iter.next() {
		match arg {
			Argument::Tag(tag) => match tag.as_str() {
				"days" => {
					if let Some(Argument::Number(days)) = iter.next() {
						request.days = *days;
					}
				}
				"subject" => {
					if let Some(Argument::Str(value)) = iter.next() {
						request.subject = Some(value.clone());
					}
				}
				"from" => {
					if let Some(Argument::Str(value)) = iter.next() {
						request.from = Some(value.clone());
					}
				}
				// `:handle` / `:addresses` carry a value that is not the reason.
				"handle" | "addresses" => {
					iter.next();
				}
				_ => {}
			},
			Argument::Str(value) => reason = Some(value.clone()),
			_ => {}
		}
	}
	reason.map(|reason| VacationRequest { reason, ..request })
}

/// `date [comparator] <header-name> <date-part> <key-list>` (RFC 5260).
fn date_test(test: &Test, message: &Message) -> bool {
	let comparator = comparator(&test.args);
	let strings = strings(&test.args);
	// Arguments are: header-name, date-part, then one or more keys.
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

/// `currentdate [comparator] <date-part> <key-list>` (RFC 5260): compares the
/// chosen part of the current (UTC) date against the keys.
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
fn address_test(test: &Test, message: &Message) -> bool {
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
				if comparator.matches(&addr, key) {
					return true;
				}
			}
		}
	}
	false
}

/// `envelope [comparator] [part] <envelope-part-list> <key-list>` (RFC 5228
/// §5.4): `from` matches MAIL FROM, `to` matches RCPT TO.
fn envelope_test(test: &Test, message: &Message) -> bool {
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
				if comparator.matches(&value, key) {
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

/// `body [comparator] [:raw|:text] <key-list>` (RFC 5173): body text vs keys
/// (the transforms all reduce to body text; no MIME decoding yet).
fn body_test(test: &Test, message: &Message) -> bool {
	let comparator = comparator(&test.args);
	let keys = strings(&test.args);
	keys.iter()
		.any(|key| comparator.matches(&message.body, key))
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

/// Flag tokens from a flag-list argument (each string may hold several flags).
fn flag_list(args: &[Argument]) -> Vec<String> {
	strings(args)
		.iter()
		.flat_map(|s| s.split_whitespace().map(str::to_string))
		.collect()
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
