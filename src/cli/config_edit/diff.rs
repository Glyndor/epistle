//! The unified diff of a configuration change, with the credentials hidden.
//!
//! The hiding walks the tree of the document, not its lines: a value
//! written as a multiline string continues on the next lines, and those
//! lines are part of the credential. A diff that hides the first line of
//! the value and prints the rest prints the secret.

use std::borrow::Cow;
use std::fmt::Write;
use std::ops::Range;
use std::path::Path;

use toml_edit::{Document, Item, Table, Value};

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

/// What replaces the value of a credential.
const REDACTED: &str = "<redacted>";

pub(super) fn unified(path: &Path, old: &str, new: &str) -> String {
	if old == new {
		return String::new();
	}
	let old_lines: Vec<_> = old.split_inclusive('\n').collect();
	let new_lines: Vec<_> = new.split_inclusive('\n').collect();
	let old_patches = patches(old, &old_lines);
	let new_patches = patches(new, &new_lines);
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
	for (index, line) in old_lines[start..prefix].iter().enumerate() {
		emit(&mut output, ' ', line, &old_patches[start + index]);
	}
	for (index, line) in old_lines[prefix..old_lines.len() - suffix]
		.iter()
		.enumerate()
	{
		emit(&mut output, '-', line, &old_patches[prefix + index]);
	}
	for (index, line) in new_lines[prefix..new_lines.len() - suffix]
		.iter()
		.enumerate()
	{
		emit(&mut output, '+', line, &new_patches[prefix + index]);
	}
	for (index, line) in old_lines[old_lines.len() - suffix..old_end]
		.iter()
		.enumerate()
	{
		emit(
			&mut output,
			' ',
			line,
			&old_patches[old_lines.len() - suffix + index],
		);
	}
	output
}

fn emit(output: &mut String, marker: char, line: &str, patches: &[Patch]) {
	let line_owned = apply(line, patches);
	output.push(marker);
	output.push_str(line_owned.as_ref());
	if !line.ends_with('\n') {
		output.push_str("\n\\ No newline at end of file\n");
	}
}

/// A range of bytes inside a line, and what replaces it.
struct Patch {
	/// The byte offset inside the line where the range starts.
	start: usize,
	/// The byte offset inside the line where the range ends.
	end: usize,
	/// What replaces the range.
	text: String,
}

/// The redactions of one document: one entry per line of it, in order.
type Patches = Vec<Vec<Patch>>;

/// The redactions of `text`, one entry per line of `lines`.
///
/// The tree of the document says where each credential is: the value of a
/// secret key, with the bytes it occupies, so a value that spans several
/// lines is hidden whole.
fn patches(text: &str, lines: &[&str]) -> Patches {
	let Ok(document) = Document::parse(text) else {
		// A document that does not parse cannot be walked, and a line that
		// cannot be read may be a credential: every line goes.
		return lines
			.iter()
			.map(|line| {
				vec![Patch {
					start: 0,
					end: content_end(line),
					text: REDACTED.to_string(),
				}]
			})
			.collect();
	};
	let mut starts = Vec::with_capacity(lines.len());
	let mut offset = 0;
	for line in lines {
		starts.push(offset);
		offset += line.len();
	}
	let mut found: Vec<(usize, Patch)> = Vec::new();
	for (key, span) in credentials(document.as_table()) {
		let Some(replacement) = replacement_for(&key, &text[span.clone()]) else {
			continue;
		};
		if span.start >= span.end {
			continue;
		}
		let first = line_of(&starts, span.start);
		let last = line_of(&starts, span.end - 1);
		if first == last {
			found.push((
				first,
				Patch {
					start: span.start - starts[first],
					end: (span.end - starts[first]).min(content_end(lines[first])),
					text: replacement,
				},
			));
			continue;
		}
		// The value continues on the next lines: the first line keeps the
		// key, the lines in between are the value, and the last line ends
		// with it.
		let first_end = starts[first] + content_end(lines[first]);
		found.push((
			first,
			Patch {
				start: span.start - starts[first],
				end: first_end - starts[first],
				text: replacement,
			},
		));
		for (line, text) in lines.iter().enumerate().take(last).skip(first + 1) {
			found.push((
				line,
				Patch {
					start: 0,
					end: content_end(text),
					text: REDACTED.to_string(),
				},
			));
		}
		found.push((
			last,
			Patch {
				start: 0,
				end: (span.end - starts[last]).min(content_end(lines[last])),
				text: REDACTED.to_string(),
			},
		));
	}
	found.sort_by_key(|(line, patch)| (*line, patch.start));
	let mut patches: Patches = (0..lines.len()).map(|_| Vec::new()).collect();
	for (line, patch) in found {
		patches[line].push(patch);
	}
	patches
}

/// The line of the document that holds `offset`.
fn line_of(starts: &[usize], offset: usize) -> usize {
	starts
		.partition_point(|start| *start <= offset)
		.saturating_sub(1)
}

/// The length of `line` without its terminator.
fn content_end(line: &str) -> usize {
	let bytes = line.as_bytes();
	let mut end = bytes.len();
	if end > 0 && bytes[end - 1] == b'\n' {
		end -= 1;
	}
	if end > 0 && bytes[end - 1] == b'\r' {
		end -= 1;
	}
	end
}

/// The line with the regions of its patches replaced.
fn apply<'a>(line: &'a str, patches: &[Patch]) -> Cow<'a, str> {
	if patches.is_empty() {
		return Cow::Borrowed(line);
	}
	let mut out = String::with_capacity(line.len());
	let mut cursor = 0;
	for patch in patches {
		out.push_str(&line[cursor..patch.start]);
		out.push_str(&patch.text);
		cursor = patch.end;
	}
	out.push_str(&line[cursor..]);
	Cow::Owned(out)
}

/// The values of the document that carry a credential, with the bytes they
/// occupy in it.
fn credentials(table: &Table) -> Vec<(String, Range<usize>)> {
	let mut found = Vec::new();
	collect(table, &mut found);
	found
}

fn collect(table: &Table, found: &mut Vec<(String, Range<usize>)>) {
	for (key, item) in table.iter() {
		collect_item(key, item, found);
	}
}

fn collect_item(key: &str, item: &Item, found: &mut Vec<(String, Range<usize>)>) {
	match item {
		Item::Value(value) => collect_value(key, value, found),
		Item::Table(table) => collect(table, found),
		Item::ArrayOfTables(tables) => {
			for table in tables.iter() {
				collect(table, found);
			}
		}
		Item::None => {}
	}
}

fn collect_value(key: &str, value: &Value, found: &mut Vec<(String, Range<usize>)>) {
	if is_secret_key(key) {
		// The whole value is the credential: what it holds is part of it.
		if let Some(span) = value.span() {
			found.push((key.to_string(), span));
		}
		return;
	}
	if key == "url" {
		// A url is not a credential by itself: only its password is, and
		// only a string can carry one. A url that is not a string is
		// walked like any other key.
		if let Value::String(_) = value {
			if let Some(span) = value.span() {
				found.push((key.to_string(), span));
			}
			return;
		}
	}
	match value {
		Value::InlineTable(table) => {
			for (key, value) in table.iter() {
				collect_value(key, value, found);
			}
		}
		Value::Array(array) => {
			for element in array.iter() {
				collect_value(key, element, found);
			}
		}
		_ => {}
	}
}

/// What replaces the value of `key`: the whole value for a credential, and
/// the value without its password for a url.
fn replacement_for(key: &str, value: &str) -> Option<String> {
	if is_secret_key(key) {
		return Some(REDACTED.to_string());
	}
	match redact_url(value) {
		Some(url) => Some(url),
		// A url that cannot be parsed and spans several lines cannot be
		// repaired: it goes whole rather than leak its password.
		None if value.contains('\n') => Some(REDACTED.to_string()),
		None => None,
	}
}

fn is_secret_key(key: &str) -> bool {
	SECRET_KEYS.contains(&key)
}

/// Parse `value` (the source text of a TOML string, with its quotes) as a
/// libpq URL and return the same URL with the password portion of the
/// userinfo stripped. The shape the loader accepts is
/// `postgres://user:password@host/...`; the `?password=...` query
/// parameter is the other path. Returns `None` when the value is not a
/// URL with credentials, so the caller can keep it unchanged.
fn redact_url(value: &str) -> Option<String> {
	let trimmed = value.trim();
	if trimmed.len() < 2 || !trimmed.starts_with('"') || !trimmed.ends_with('"') {
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
