//! The numbers, error codes and webhook events `docs/api.md` states are the
//! ones the code has. Each number is read from its constant in the source and
//! must appear in the sentence that gives it; each `error.code` and each
//! webhook event name must appear in backticks.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

fn root() -> &'static Path {
	Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn source(path: &str) -> String {
	fs::read_to_string(root().join(path)).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

/// The guide with every run of white space folded to one space, so a phrase
/// can be matched across a line break.
fn guide() -> String {
	let text = fs::read_to_string(root().join("docs/api.md")).expect("read docs/api.md");
	text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The integers of a constant's initialiser, multiplied when it is a product
/// (`25 * 1024 * 1024`) and the first one otherwise (`Duration::from_secs(60)`).
fn value_of(path: &str, name: &str) -> u64 {
	let text = source(path);
	let marker = format!("const {name}:");
	let start = text
		.find(&marker)
		.unwrap_or_else(|| panic!("{path} has no `const {name}`"));
	let statement = &text[start..];
	let init = statement
		.split_once('=')
		.and_then(|(_, rest)| rest.split_once(';'))
		.map(|(init, _)| init)
		.unwrap_or_else(|| panic!("{name}: no initialiser"));
	let numbers: Vec<u64> = init
		.split(|c: char| !(c.is_ascii_digit() || c == '_'))
		.filter(|part| part.chars().any(|c| c.is_ascii_digit()))
		.map(|part| part.replace('_', "").parse().expect("an integer"))
		.collect();
	if init.contains('*') {
		numbers.iter().product()
	} else {
		numbers[0]
	}
}

fn grouped(value: u64) -> String {
	let digits = value.to_string();
	let mut out = String::new();
	for (at, c) in digits.chars().enumerate() {
		if at > 0 && (digits.len() - at).is_multiple_of(3) {
			out.push(',');
		}
		out.push(c);
	}
	out
}

/// `{}` in `phrase` stands for the value of the next constant, `{,}` for one
/// written with thousands separators, `{MiB}` for one in mebibytes.
fn fill(phrase: &str, values: &[u64]) -> String {
	let mut out = String::new();
	let mut rest = phrase;
	let mut values = values.iter();
	while let Some(at) = rest.find('{') {
		out.push_str(&rest[..at]);
		let end = rest[at..].find('}').expect("a closing brace") + at;
		let value = *values.next().expect("a value for every placeholder");
		out.push_str(&match &rest[at + 1..end] {
			"" => value.to_string(),
			"," => grouped(value),
			"MiB" => (value / 1_048_576).to_string(),
			other => panic!("unknown placeholder {other}"),
		});
		rest = &rest[end + 1..];
	}
	out.push_str(rest);
	out
}

const SEND: &str = "src/api/v1/send_request.rs";
const JMAP: &str = "src/api/jmap/limits.rs";

/// (file, constants, phrase of docs/api.md that carries them).
const NUMBERS: &[(&str, &[&str], &str)] = &[
	(
		SEND,
		&["MAX_CUSTOM_HEADERS"],
		"Custom headers: up to {}, name",
	),
	(SEND, &["MAX_PARTS"], "At most {} parts together"),
	(SEND, &["MAX_REFERENCES"], "up to {} for `references`"),
	(SEND, &["MAX_UNSUBSCRIBE"], "Up to {} `mailto:`"),
	(SEND, &["MAX_EXTRA_KEYS"], "up to {} keys (printable ASCII"),
	(
		SEND,
		&["MAX_EXTRA_KEY_LEN"],
		"at most {} bytes) with values",
	),
	(SEND, &["MAX_EXTRA_VALUE_LEN"], "values of at most {} bytes"),
	(
		"src/api/state_bearer.rs",
		&["MAX_BEARER_LEN"],
		"longer than {} bytes is not looked at",
	),
	(
		"src/api/state_limiter.rs",
		&["AUTH_MAX_FAILURES"],
		"made {} requests with credentials",
	),
	(
		"src/api/state_limiter.rs",
		&["AUTH_WINDOW"],
		"in the last {} seconds",
	),
	(
		"src/api/state.rs",
		&["MAX_CONCURRENT_ARGON2", "MAX_ARGON2_QUEUE"],
		"argon2 check: {} run at a time, {} may wait",
	),
	(
		"src/smtp/session/mod.rs",
		&["DEFAULT_MAX_RECIPIENTS"],
		"Together at most {}",
	),
	(
		"src/smtp/session/mod.rs",
		&["MAX_MESSAGE_SIZE"],
		"{MiB} MiB by default",
	),
	(JMAP, &["MAX_SIZE_REQUEST"], "{,} octets per request"),
	(JMAP, &["MAX_CALLS_IN_REQUEST"], "{} calls, "),
	(
		JMAP,
		&["MAX_OBJECTS_IN_GET"],
		"{} objects per `/get` or `/set`",
	),
	(
		JMAP,
		&["MAX_CONCURRENT_REQUESTS", "MAX_CONCURRENT_UPLOAD"],
		"{} requests and {} uploads in flight",
	),
	(
		"src/api/jmap/event_source.rs",
		&["MAX_STREAMS_PER_CALLER"],
		"{} event streams per credential",
	),
	("src/api/v1/queue.rs", &["MAX_LIMIT"], "(`limit` 1 to {}"),
	(
		"src/api/v1/deliveries.rs",
		&["DEFAULT_LIMIT"],
		"default {}. There is no cursor",
	),
	(
		"src/storage/delivery_log.rs",
		&["DEFAULT_DELIVERY_LOG_DAYS"],
		"({} by default)",
	),
	(
		"src/password/mod.rs",
		&["MIN_LENGTH", "MAX_LENGTH"],
		"{} to {} printable ASCII",
	),
	(
		"src/directory_store/display_name.rs",
		&["MAX_CHARS"],
		"At most {} characters",
	),
	(
		"src/net/http_serve.rs",
		&["HEADER_READ_TIMEOUT"],
		"{} seconds to send it",
	),
];

#[test]
fn every_number_in_the_guide_is_the_one_in_the_code() {
	let guide = guide();
	for (file, names, phrase) in NUMBERS {
		let values: Vec<u64> = names.iter().map(|name| value_of(file, name)).collect();
		let wanted = fill(phrase, &values);
		assert!(
			guide.contains(&wanted),
			"docs/api.md should say {wanted:?} ({names:?} in {file}); update the guide or the code"
		);
	}
}

#[test]
fn the_webhook_timeout_is_the_one_in_the_guide() {
	assert!(source("src/webhook.rs").contains("timeout(Duration::from_secs(15))"));
	assert!(guide().contains("with a 15 second timeout and no retry"));
}

/// The `code: "..."` strings of `ApiError`.
fn error_codes() -> BTreeSet<String> {
	let text = source("src/api/error.rs");
	let production = text.split("#[cfg(test)]").next().expect("source");
	production
		.lines()
		.filter_map(|line| line.trim().strip_prefix("code: \""))
		.filter_map(|rest| rest.split('"').next())
		.map(str::to_string)
		.collect()
}

#[test]
fn every_error_code_is_in_the_guide() {
	let guide = guide();
	let codes = error_codes();
	assert!(codes.len() >= 15, "{codes:?}");
	for code in codes {
		assert!(
			guide.contains(&format!("`{code}`")),
			"docs/api.md does not name the error code `{code}`"
		);
	}
}

fn snake_case(name: &str) -> String {
	let mut out = String::new();
	for (at, c) in name.chars().enumerate() {
		if c.is_ascii_uppercase() {
			if at > 0 {
				out.push('_');
			}
			out.push(c.to_ascii_lowercase());
		} else {
			out.push(c);
		}
	}
	out
}

/// The `event` names of `WebhookEvent`, honouring `#[serde(rename = "...")]`.
fn webhook_events() -> BTreeSet<String> {
	let text = source("src/webhook.rs");
	let body = text
		.split("pub enum WebhookEvent {")
		.nth(1)
		.and_then(|rest| rest.split("\n}\n").next())
		.expect("the enum");
	let mut events = BTreeSet::new();
	let mut renamed: Option<String> = None;
	for line in body.lines() {
		let line = line.trim_start_matches('\t');
		if line.starts_with('\t') || line.starts_with("//") {
			continue;
		}
		if let Some(rest) = line.strip_prefix("#[serde(rename = \"") {
			renamed = rest.split('"').next().map(str::to_string);
			continue;
		}
		let first = line.chars().next().unwrap_or(' ');
		if first.is_ascii_uppercase() {
			let ident: String = line
				.chars()
				.take_while(|c| c.is_ascii_alphanumeric())
				.collect();
			events.insert(renamed.take().unwrap_or_else(|| snake_case(&ident)));
		}
	}
	events
}

#[test]
fn every_webhook_event_is_in_the_guide() {
	let guide = guide();
	let events = webhook_events();
	assert!(events.len() >= 12, "{events:?}");
	for event in events {
		assert!(
			guide.contains(&format!("`{event}`")),
			"docs/api.md does not name the webhook event `{event}`"
		);
	}
}

#[test]
fn the_links_in_the_guide_lead_somewhere() {
	let text = fs::read_to_string(root().join("docs/api.md")).expect("read docs/api.md");
	for target in text
		.split("](")
		.skip(1)
		.filter_map(|rest| rest.split(')').next())
	{
		let path = target.split('#').next().unwrap_or("");
		if path.is_empty() || path.starts_with("http") {
			continue;
		}
		assert!(
			root().join("docs").join(path).exists(),
			"docs/api.md links to {target}, which does not exist"
		);
	}
}

#[test]
fn verify_scope_documentation_excludes_account_bound_keys() {
	let text = guide();
	assert!(text.contains("administrative keys without `account` or `domains`"));
	assert!(text.contains("Account-bound keys cannot access `/api/v1/auth/verify`"));
}
