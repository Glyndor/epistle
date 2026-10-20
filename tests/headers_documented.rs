//! `docs/headers.md` names every header the source writes or removes.
//!
//! The page is what an integrator reads to learn which headers to trust, so
//! it cannot fall behind the code. This reads the production source for the
//! names that reach a message and fails for one the page does not mention in
//! backticks, and for a "never added" name the source does write.
//!
//! A name is found in four ways: a string that starts a header line
//! (`"Received: ..."`, `\r\nX-Spam-Score: ...`), the name argument of the
//! `address_list`, `structured` and `unstructured` writers, a constant whose
//! identifier says `HEADER` or `FIELD`, and the names in the list a
//! `strip_headers` call is given. Anything that looks like one and is not
//! goes in [`NOT_HEADERS`], with the reason.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Names the scan finds that are not headers of a message.
const NOT_HEADERS: &[(&str, &str)] = &[
	("Proc-Type", "a PEM key header in the key importer"),
	("Report-ID", "text inside the subject of a DMARC report"),
	(
		"Content-Length",
		"a header of the HTTP refusal a full listener sends, not of a message",
	),
	(
		"Retry-After",
		"a header of the HTTP refusal a full listener sends, not of a message",
	),
];

/// Single-word names that count as headers; any name with a hyphen does.
const SINGLE_WORD: &[&str] = &[
	"Received",
	"Date",
	"From",
	"To",
	"Cc",
	"Bcc",
	"Subject",
	"Sender",
	"Importance",
	"Precedence",
	"Action",
	"Status",
	"Version",
];

fn root() -> &'static Path {
	Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// `source` up to its test module: the first `#[cfg(test)]` followed, past
/// other attributes, by a `mod`.
fn production_part(source: &str) -> &str {
	let lines: Vec<&str> = source.split_inclusive('\n').collect();
	let mut offset = 0;
	for (at, line) in lines.iter().enumerate() {
		if line.trim() == "#[cfg(test)]" {
			let next = lines[at + 1..]
				.iter()
				.map(|line| line.trim())
				.find(|line| !line.starts_with("#["));
			if next.is_some_and(|line| line.starts_with("mod ") || line.starts_with("pub mod ")) {
				return &source[..offset];
			}
		}
		offset += line.len();
	}
	source
}

fn is_test_file(path: &Path) -> bool {
	let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
	stem == "tests"
		|| stem == "fake"
		|| stem == "test_support"
		|| stem.starts_with("tests_")
		|| stem.ends_with("_tests")
		|| stem.contains("_tests_")
		|| path.components().any(|part| part.as_os_str() == "tests")
}

fn sources(dir: &Path, out: &mut Vec<PathBuf>) {
	for entry in fs::read_dir(dir).expect("read dir") {
		let path = entry.expect("entry").path();
		if path.is_dir() {
			sources(&path, out);
		} else if path.extension().is_some_and(|ext| ext == "rs") && !is_test_file(&path) {
			out.push(path);
		}
	}
}

/// The code of `source` without whole-line comments.
fn code_of(source: &str) -> String {
	production_part(source)
		.lines()
		.filter(|line| !line.trim_start().starts_with("//"))
		.collect::<Vec<_>>()
		.join("\n")
}

fn is_name_char(c: char) -> bool {
	c.is_ascii_alphanumeric() || c == '-'
}

/// Names that start a header line inside a string literal.
fn literal_names(code: &str, found: &mut BTreeSet<String>) {
	let chars: Vec<char> = code.chars().collect();
	for (at, &c) in chars.iter().enumerate() {
		if c != ':' {
			continue;
		}
		let after: String = chars[at + 1..].iter().take(2).collect();
		let boundary = after.is_empty()
			|| after.starts_with([' ', '{', '"'])
			|| after.starts_with("\\r")
			|| after.starts_with("\\n");
		if !boundary {
			continue;
		}
		let mut start = at;
		while start > 0 && is_name_char(chars[start - 1]) {
			start -= 1;
		}
		// `\r\nName`: the letter after a backslash belongs to the escape.
		if start > 0 && chars[start - 1] == '\\' {
			start += 1;
		}
		let name: String = chars[start..at].iter().collect();
		let upper = name.chars().next().is_some_and(|c| c.is_ascii_uppercase());
		if upper && (name.contains('-') || SINGLE_WORD.contains(&name.as_str())) {
			found.insert(name);
		}
	}
}

/// The `"Name"` argument of the header writers.
fn writer_names(code: &str, found: &mut BTreeSet<String>) {
	for writer in ["address_list(", "structured(", "unstructured("] {
		for (at, _) in code.match_indices(writer) {
			let rest = code[at + writer.len()..].trim_start();
			if let Some(quoted) = rest.strip_prefix('"')
				&& let Some((name, _)) = quoted.split_once('"')
				&& name.chars().all(is_name_char)
			{
				found.insert(name.to_string());
			}
		}
	}
}

/// `const SOMETHING_HEADER: &str = "Name";` and the same with `FIELD`.
fn constant_names(code: &str, found: &mut BTreeSet<String>) {
	for line in code.lines() {
		let line = line.trim();
		let Some(rest) = line
			.strip_prefix("pub const ")
			.or_else(|| line.strip_prefix("const "))
			.or_else(|| line.strip_prefix("pub(crate) const "))
		else {
			continue;
		};
		let Some((ident, value)) = rest.split_once(": &str = \"") else {
			continue;
		};
		if (ident.contains("HEADER") || ident.contains("FIELD"))
			&& let Some((name, _)) = value.split_once('"')
			&& name.chars().all(is_name_char)
		{
			found.insert(name.to_string());
		}
	}
}

/// The text up to the parenthesis that closes a call whose `(` was just read.
fn arguments(after_open: &str) -> &str {
	let mut depth = 1usize;
	for (at, c) in after_open.char_indices() {
		match c {
			'(' => depth += 1,
			')' => {
				depth -= 1;
				if depth == 0 {
					return &after_open[..at];
				}
			}
			_ => {}
		}
	}
	after_open
}

/// The names in the `&["a", "b"]` list of a `strip_headers` call.
fn stripped_names(code: &str, found: &mut BTreeSet<String>) {
	for call in ["strip_headers(", "strip_headers_in_place("] {
		for (at, _) in code.match_indices(call) {
			if code[..at].ends_with("fn ") {
				continue;
			}
			let args = arguments(&code[at + call.len()..]);
			let Some(list) = args
				.split_once("&[")
				.and_then(|(_, rest)| rest.split_once(']'))
			else {
				continue;
			};
			for part in list.0.split(',') {
				let quoted = part
					.trim()
					.strip_prefix('"')
					.and_then(|p| p.strip_suffix('"'));
				if let Some(name) = quoted.filter(|name| name.chars().all(is_name_char)) {
					found.insert(name.to_string());
				}
			}
		}
	}
}

/// Every header name the production source writes or removes, lowercase.
fn written() -> BTreeSet<String> {
	let mut files = Vec::new();
	sources(&root().join("src"), &mut files);
	let mut found = BTreeSet::new();
	for file in files {
		let code = code_of(&fs::read_to_string(&file).expect("read source"));
		literal_names(&code, &mut found);
		writer_names(&code, &mut found);
		constant_names(&code, &mut found);
		stripped_names(&code, &mut found);
	}
	let skip: BTreeSet<String> = NOT_HEADERS
		.iter()
		.map(|(name, _)| name.to_ascii_lowercase())
		.collect();
	found
		.into_iter()
		.map(|name| name.to_ascii_lowercase())
		.filter(|name| !skip.contains(name))
		.collect()
}

fn page() -> String {
	fs::read_to_string(root().join("docs/headers.md")).expect("read docs/headers.md")
}

/// The words the page puts in backticks, lowercase.
fn backticked(text: &str) -> BTreeSet<String> {
	text.split('`')
		.skip(1)
		.step_by(2)
		.map(|word| word.trim().to_ascii_lowercase())
		.collect()
}

#[test]
fn the_page_names_every_header_the_source_writes_or_removes() {
	let documented = backticked(&page());
	let missing: Vec<String> = written()
		.into_iter()
		.filter(|name| !documented.contains(name))
		.collect();
	assert!(
		missing.is_empty(),
		"docs/headers.md does not mention these headers the source writes or removes (put each in backticks in the tables there, or, if it is not a header of a message, add it to NOT_HEADERS in tests/headers_documented.rs with the reason): {missing:?}"
	);
}

#[test]
fn the_scan_finds_the_headers_it_is_meant_to() {
	let found = written();
	for name in [
		"received",
		"return-path",
		"delivered-to",
		"authentication-results",
		"received-spf",
		"dkim-signature",
		"arc-seal",
		"x-spam-score",
		"x-spam-status",
		"x-epistle-attachment-warning",
		"epistle-class",
		"auto-submitted",
		"feedback-id",
		"list-unsubscribe-post",
		"bcc",
		"resent-bcc",
		"tls-required",
		"in-reply-to",
		"reply-to",
		"message-id",
	] {
		assert!(found.contains(name), "the scan no longer finds {name}");
	}
}

#[test]
fn nothing_listed_as_never_added_is_written() {
	let page = page();
	let start = page
		.find("**Never added, on any path:**")
		.expect("the never-added paragraph");
	let paragraph = &page[start..];
	let end = paragraph.find("**Never leaves").expect("its end");
	let never = backticked(&paragraph[..end]);
	assert!(never.len() >= 8, "{never:?}");
	let found = written();
	let written_anyway: Vec<&String> = never.iter().filter(|name| found.contains(*name)).collect();
	assert!(
		written_anyway.is_empty(),
		"docs/headers.md says these are never added, and the source writes them: {written_anyway:?}"
	);
}

#[test]
fn the_page_keeps_its_warning_about_planned_changes() {
	let page = page();
	assert!(page.contains("## Planned changes"));
	assert!(page.contains("Do not depend on any of them yet"));
}
