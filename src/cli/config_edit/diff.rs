use std::borrow::Cow;
use std::fmt::Write;
use std::path::Path;

/// Names of fields whose value is a credential and so must never reach a
/// dry-run diff in plaintext. The list is named after the TOML keys the
/// server reads, not after the runtime structs: a wrong field name here
/// would silently leak a secret, and the danger is asymmetric.
/// `password` covers `[transport]`, account passwords that round-trip
/// through the config, and any other ad-hoc named field; the rest are
/// single-purpose credentials with no equivalent name.
const SECRET_KEYS: &[&str] = &[
	"password",
	"secret",
	"token",
	"token_hash",
	"password_hash",
	"access_key",
	"consumer_key",
	"signing_key",
	"bind_password",
	"srs_secret",
	"secret_access_key",
	"secret_key",
	"public_key",
];

pub(super) fn unified(path: &Path, old: &str, new: &str) -> String {
	if old == new {
		return String::new();
	}
	let old_lines: Vec<_> = old.split_inclusive('\n').collect();
	let new_lines: Vec<_> = new.split_inclusive('\n').collect();
	let prefix = old_lines
		.iter()
		.zip(&new_lines)
		.take_while(|(a, b)| a == b)
		.count();
	let suffix = old_lines[prefix..]
		.iter()
		.rev()
		.zip(new_lines[prefix..].iter().rev())
		.take_while(|(a, b)| a == b)
		.count();
	let start = prefix.saturating_sub(3);
	let old_end = (old_lines.len() - suffix + 3).min(old_lines.len());
	let new_end = (new_lines.len() - suffix + 3).min(new_lines.len());
	let mut output = format!("--- {}\n+++ {}\n", path.display(), path.display());
	let _ = writeln!(
		output,
		"@@ -{},{} +{},{} @@",
		if old_end == start { start } else { start + 1 },
		old_end - start,
		if new_end == start { start } else { start + 1 },
		new_end - start
	);
	for line in &old_lines[start..prefix] {
		emit(&mut output, ' ', line);
	}
	for line in &old_lines[prefix..old_lines.len() - suffix] {
		emit(&mut output, '-', line);
	}
	for line in &new_lines[prefix..new_lines.len() - suffix] {
		emit(&mut output, '+', line);
	}
	for line in &old_lines[old_lines.len() - suffix..old_end] {
		emit(&mut output, ' ', line);
	}
	output
}

fn emit(output: &mut String, marker: char, line: &str) {
	let line_owned: Cow<str> = redact(line);
	output.push(marker);
	output.push_str(line_owned.as_ref());
	if !line.ends_with('\n') {
		output.push_str("\n\\ No newline at end of file\n");
	}
}

/// Return `line` unchanged, or with the value redacted when `line`
/// assigns to a known secret key. A line that matches `<key> = <value>`
/// with a redacted key has its value replaced with `<redacted>` while
/// the marker, key, surrounding whitespace and trailing comment stay
/// intact, so the diff still shows the line moved.
///
/// `url` is treated specially: a `postgres://user:pass@host/db` value
/// has only the password portion of the userinfo replaced, leaving the
/// user name and host visible; other url shapes fall back to the plain
/// redaction.
fn redact(line: &str) -> Cow<'_, str> {
	let Some(assignment) = find_assignment(line) else {
		return Cow::Borrowed(line);
	};
	let key: &str = &line[assignment.key_start..assignment.key_end];
	let mut value_end = assignment.value_end;
	let bytes = line.as_bytes();
	// Preserve trailing whitespace before the trailing comment, so a
	// `key = "value" # comment` line ends up `key = <redacted> # comment`,
	// not `key = <redacted># comment`. A bare `key = "value"` line is
	// unaffected (no whitespace before the line break).
	while value_end > assignment.value_start
		&& (bytes[value_end - 1] == b' ' || bytes[value_end - 1] == b'\t')
	{
		value_end -= 1;
	}
	let value = &line[assignment.value_start..value_end];
	let replacement = if is_secret_key(key) {
		Some("<redacted>".to_string())
	} else if key == "url" {
		redact_url(value)
	} else {
		None
	};
	let Some(replacement) = replacement else {
		return Cow::Borrowed(line);
	};
	let mut out = String::with_capacity(line.len());
	out.push_str(&line[..assignment.value_start]);
	out.push_str(&replacement);
	out.push_str(&line[value_end..]);
	Cow::Owned(out)
}

/// Find the start and end of `<key> = <value>` in `line`. Returns the
/// byte indices of the key, the value, and the trailing comment, so
/// the caller can keep the prefix and suffix byte-for-byte and only
/// rewrite the value. `value_start` is the first non-whitespace byte
/// after `=`, `value_end` is the byte just before any trailing comment
/// or line ending. Indices use the same convention as
/// `String::chars`/`str` slicing.
struct Assignment {
	key_start: usize,
	key_end: usize,
	value_start: usize,
	value_end: usize,
}

fn find_assignment(line: &str) -> Option<Assignment> {
	let bytes = line.as_bytes();
	let mut idx = 0;
	// Skip any leading non-blank diff marker the editor would have added.
	if let Some(&b) = bytes.first()
		&& !b.is_ascii_whitespace()
		&& (b == b'+' || b == b'-' || b == b' ')
	{
		idx = 1;
	}
	while idx < bytes.len() && bytes[idx] == b' ' {
		idx += 1;
	}
	let key_start = idx;
	while idx < bytes.len()
		&& bytes[idx] != b'='
		&& bytes[idx] != b'\n'
		&& bytes[idx] != b'#'
		&& bytes[idx] != b' '
		&& bytes[idx] != b'\t'
	{
		idx += 1;
	}
	let key_end = idx;
	let key = &line[key_start..key_end];
	if key.is_empty() {
		return None;
	}
	if !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
		return None;
	}
	// Skip whitespace between the key and the `=`.
	while idx < bytes.len() && (bytes[idx] == b' ' || bytes[idx] == b'\t') {
		idx += 1;
	}
	if idx >= bytes.len() || bytes[idx] != b'=' {
		return None;
	}
	idx += 1;
	while idx < bytes.len() && bytes[idx] == b' ' {
		idx += 1;
	}
	let value_start = idx;
	while idx < bytes.len() && bytes[idx] != b'\n' && bytes[idx] != b'#' {
		idx += 1;
	}
	let value_end = idx;
	Some(Assignment {
		key_start,
		key_end,
		value_start,
		value_end,
	})
}

fn is_secret_key(key: &str) -> bool {
	SECRET_KEYS.contains(&key)
}

/// Parse `value` (the RHS of a `key = ...` line, with surrounding quotes
/// and whitespace preserved by the caller) as a libpq URL and return the
/// same URL with the password portion of the userinfo stripped. The
/// shape the loader accepts is `postgres://user:password@host/...`; the
/// `?password=...` query parameter is the other path. Returns `None`
/// when the value is not a URL with credentials, so the caller can keep
/// it unchanged.
fn redact_url(value: &str) -> Option<String> {
	let trimmed = value.trim();
	if !trimmed.starts_with('"') || !trimmed.ends_with('"') {
		return None;
	}
	let inner = &trimmed[1..trimmed.len() - 1];
	let mut url = url::Url::parse(inner).ok()?;
	let had_userinfo_password = url.password().is_some();
	let mut has_query_password = false;
	for (k, _) in url.query_pairs() {
		if k == "password" {
			has_query_password = true;
			break;
		}
	}
	if !had_userinfo_password && !has_query_password {
		return None;
	}
	if had_userinfo_password {
		let _ = url.set_password(Some("REDACTED"));
	}
	if has_query_password {
		let kept: Vec<(String, String)> = url
			.query_pairs()
			.filter(|(k, _)| k != "password")
			.map(|(k, v)| (k.into_owned(), v.into_owned()))
			.collect();
		url.set_query(None);
		for (k, v) in &kept {
			url.query_pairs_mut().append_pair(k, v);
		}
	}
	let redacted = url.to_string();
	Some(format!("\"{redacted}\""))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn secret_lines_have_their_value_replaced() {
		assert_eq!(
			redact("-password = \"hunter2\"\n").as_ref(),
			"-password = <redacted>\n"
		);
		assert_eq!(
			redact("+secret = \"top\"\n").as_ref(),
			"+secret = <redacted>\n"
		);
		assert_eq!(
			redact("+srs_secret = \"xyz\"\n").as_ref(),
			"+srs_secret = <redacted>\n"
		);
		assert_eq!(
			redact("+signing_key = \"abc\"\n").as_ref(),
			"+signing_key = <redacted>\n"
		);
		assert_eq!(
			redact("+bind_password = \"pw\"\n").as_ref(),
			"+bind_password = <redacted>\n"
		);
		assert_eq!(
			redact(" token = \"abc\"\n").as_ref(),
			" token = <redacted>\n"
		);
	}

	#[test]
	fn non_secret_lines_remain_unchanged() {
		let line = "-hostname = 'mail.example.org' # ${{PATH}}\n";
		assert_eq!(redact(line).as_ref(), line);
		let line = "+quota_bytes = 456 # cap\n";
		assert_eq!(redact(line).as_ref(), line);
	}

	#[test]
	fn url_with_userinfo_has_password_only_redacted() {
		let line = "+url = \"postgres://user:secret@host/db\"\n";
		let redacted = redact(line);
		assert!(!redacted.contains("secret"), "redacted URL: {redacted}");
		assert!(
			redacted.contains("user:"),
			"user name must survive redaction: {redacted}"
		);
		assert!(
			redacted.contains("@host/db"),
			"host must survive redaction: {redacted}"
		);
	}

	#[test]
	fn url_without_credentials_passes_through() {
		let line = "+url = \"postgres://user@host/db\"\n";
		assert_eq!(redact(line).as_ref(), line);
	}

	#[test]
	fn secret_value_with_trailing_comment_still_redacts() {
		let line = "-password = \"abc\" # old\n";
		assert_eq!(redact(line).as_ref(), "-password = <redacted> # old\n");
	}

	#[test]
	fn unchanged_secret_lines_still_show_the_change() {
		let output = unified(
			Path::new("mail.toml"),
			"secret = \"old\"\nsecret2 = \"k2\"\n",
			"secret = \"new\"\nsecret2 = \"k2\"\n",
		);
		assert!(output.contains("-secret = <redacted>"), "{output}");
		assert!(output.contains("+secret = <redacted>"), "{output}");
		assert!(
			output.contains("secret2 = \"k2\""),
			"non-secret context lines keep their value: {output}"
		);
	}
}
