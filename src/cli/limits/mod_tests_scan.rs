//! The scan that ties the catalog to the code: every constant that reads as a
//! limit in the protocol modules is a row of `protocol.rs` or is
//! excused here with a reason.

use std::collections::BTreeSet;
use std::path::Path;

use super::*;

/// The directories of the protocol modules, under `src/`. Every file in
/// them is read, so a new file is scanned without being listed here.
const SCANNED_DIRS: &[&str] = &[
	"smtp",
	"pop3",
	"imap",
	"managesieve",
	"sieve",
	"api/jmap",
	"spf",
];

/// Single files outside those directories that hold limits a client meets:
/// the address and header rules, and the mailbox name rules.
const SCANNED_FILES: &[&str] = &[
	"util/validation/mod.rs",
	"util/mailbox_path.rs",
	"util/header.rs",
	"webdav/caldav_busy.rs",
	"webdav/quota.rs",
	"webdav/bounds.rs",
];

/// Constants that are not a row of their own, each with the reason. The
/// first group backs an adjustable key (its default or its ceiling), which
/// the key's own row already shows.
const NOT_A_ROW: &[(&str, &str)] = &[
	(
		"smtp::session::MAX_MESSAGE_SIZE",
		"the default of the adjustable max-message-size",
	),
	(
		"smtp::session::MIN_MESSAGE_SIZE",
		"the MUST floor of the adjustable max-message-size",
	),
	(
		"smtp::session::MIN_MAX_RECIPIENTS",
		"the MUST floor of the adjustable max-recipients",
	),
	(
		"smtp::session::MAX_MAX_RECIPIENTS",
		"the ceiling of the adjustable max-recipients",
	),
	(
		"smtp::server::MAX_CONNECTIONS",
		"the protocol default of max-connections-per-listener",
	),
	(
		"smtp::server::MAX_CONNECTIONS_PER_IP",
		"the default of the adjustable max-connections-per-ip",
	),
	(
		"pop3::server::MAX_CONNECTIONS",
		"the protocol default of max-connections-per-listener",
	),
	(
		"imap::server::MAX_CONNECTIONS",
		"the protocol default of max-connections-per-listener",
	),
	(
		"managesieve::server::MAX_CONNECTIONS",
		"the protocol default of max-connections-per-listener",
	),
	(
		"pop3::log_gate::MAX_KEYS",
		"internal: how many log notices are remembered",
	),
	(
		"smtp::scram::SALT_LEN",
		"internal: the salt of a stored SCRAM credential",
	),
	(
		"smtp::scram::SCRAM_ITERATIONS",
		"internal: the work factor of a stored SCRAM credential",
	),
	(
		"smtp::memory_budget::DEFAULT_BUDGET_BYTES",
		"internal: the memory budget used when none is derived",
	),
	(
		"imap::session::fetch::PREVIEW_LEN",
		"internal: the characters a PREVIEW fetch returns",
	),
	(
		"imap::session::state::DEFAULT_QUOTA_BYTES",
		"the default of the adjustable quota",
	),
	(
		"managesieve::store_check::MAX_SHOWN",
		"internal: the problems a script check lists",
	),
	(
		"managesieve::store_names::FILE_NAME_BYTES",
		"internal: where a name stops being its file name, the limit a client meets is managesieve-script-name-bytes",
	),
	(
		"api::jmap::blob_path::NAME_LEN",
		"internal: the length of a blob file name",
	),
	(
		"api::jmap::address_tokenizer::MAX_ENCODED_WORD_LEN",
		"internal: the longest encoded word the address tokenizer decodes",
	),
	(
		"spf::evaluator::MAX_DEPTH",
		"bounded by spf-max-dns-lookups, every include costs one lookup",
	),
	(
		"smtp::memory_fit::LIMIT_DIVISOR",
		"internal: how the derived memory budget is worked out",
	),
	(
		"smtp::memory_fit::MAX_DERIVED_BUDGET",
		"internal: the ceiling of the memory budget derived from the container limit",
	),
	(
		"smtp::memory_fit::FALLBACK_LIMIT",
		"internal: the memory assumed when no container limit is found",
	),
	(
		"smtp::memory_fit::MAX_FILE_BYTES",
		"internal: the most read from a cgroup file",
	),
	(
		"smtp::memory_fit::MAX_CGROUP_DEPTH",
		"internal: how deep the cgroup tree is followed",
	),
	(
		"smtp::server::DEFAULT_MAX_CONNECTIONS_PER_IP",
		"the default of the adjustable max-connections-per-ip",
	),
	(
		"smtp::server::data_rate::DEFAULT_MIN_DATA_RATE",
		"the default of the adjustable min-data-rate",
	),
	(
		"smtp::server::session_time::DEFAULT_MAX_SESSION_TIME_SECS",
		"the default of the adjustable max-session-time",
	),
	(
		"smtp::session::DEFAULT_MAX_RECIPIENTS",
		"the default of the adjustable max-recipients",
	),
	(
		"smtp::session::junk::DEFAULT_JUNK_COMMAND_LIMIT",
		"the default of the adjustable junk-command-limit",
	),
	(
		"smtp::ratelimit::MAX_ENTRIES",
		"internal: the size of the rate limiter's table",
	),
	(
		"imap::fetch::MAX_DEPTH",
		"internal: how deep a message structure is walked",
	),
	(
		"imap::changelog::MAX_JOURNAL_BYTES",
		"internal: the largest change journal read",
	),
	(
		"imap::session::base_subject::MAX_SUBJECT",
		"internal: the subject length SORT and THREAD compare",
	),
	(
		"imap::session::thread_references::msgid::MAX_REFERENCES",
		"internal: the references THREAD follows",
	),
	(
		"imap::session::thread_references::msgid::MAX_MSGID_LEN",
		"internal: the message id length THREAD compares",
	),
	(
		"imap::command::parse::DEFAULT_APPEND_LIMIT",
		"internal: the APPENDLIMIT it advertises is the message size cap (max-message-size)",
	),
	(
		"managesieve::server::DEFAULT_MAX_LITERAL",
		"the same number as managesieve-script-size",
	),
	(
		"managesieve::store_index::MAX_INDEX_BYTES",
		"internal: the largest script index file read",
	),
	(
		"managesieve::store_names::MAX_SIDECAR_BYTES",
		"internal: the largest name file read",
	),
	(
		"sieve::key_set::MIN_KEYS",
		"internal: when a test with many keys is indexed",
	),
	(
		"sieve::key_set::MAX_KEY_BYTES",
		"internal: the memory one indexed test may take",
	),
	(
		"sieve::vacation::MAX_REFERENCES",
		"internal: the references a vacation reply carries",
	),
	(
		"api::jmap::mime::MAX_MIME_DEPTH",
		"internal: how deep a stored message is parsed",
	),
	(
		"api::jmap::uploads::MAX_BLOBS",
		"internal: the blob ids read ahead for one request",
	),
	(
		"api::jmap::uploads::MAX_WASTED_READS",
		"internal: reads without progress before an upload is dropped",
	),
	(
		"api::jmap::uploads::MAX_DEPTH",
		"internal: how deep a blob reference is followed",
	),
	(
		"api::jmap::sieve_script_query::MAX_COMPARATORS",
		"internal: the comparators a script query inspects",
	),
	(
		"api::jmap::email_build_parts::MAX_DEPTH",
		"internal: how deep a built message nests",
	),
	(
		"util::header::MAX_HEADER_VALUE_LEN",
		"internal: caps a sanitised header value so one input cannot inflate a line",
	),
];

/// Whether a file holds tests or their support: `x_tests.rs`,
/// `x_tests_y.rs`, `tests.rs`, `x_test_support.rs`.
fn is_test_file(name: &str) -> bool {
	let stem = name.trim_end_matches(".rs");
	stem == "tests"
		|| stem.starts_with("tests_")
		|| stem.ends_with("_tests")
		|| stem.contains("_tests_")
		|| stem.contains("_test_support")
}

/// The source up to the module of tests (`#[cfg(test)]` followed by `mod`).
/// A `#[cfg(test)]` on a single item does not end the code.
fn without_test_module(text: &str) -> String {
	let lines: Vec<&str> = text.lines().collect();
	let end = (0..lines.len())
		.find(|&i| {
			lines[i].trim() == "#[cfg(test)]"
				&& lines.get(i + 1).is_some_and(|next| {
					let next = next.trim_start();
					next.starts_with("mod ") || next.starts_with("pub mod ")
				})
		})
		.unwrap_or(lines.len());
	lines[..end].join("\n")
}

/// The module path of a source file under `src/`, as `a::b`; a `mod.rs`
/// is the module of its directory.
fn module_of(relative: &Path) -> String {
	let mut parts: Vec<String> = relative
		.iter()
		.map(|part| part.to_string_lossy().into_owned())
		.collect();
	if let Some(last) = parts.last_mut() {
		*last = last.trim_end_matches(".rs").to_string();
	}
	if parts.last().is_some_and(|last| last == "mod") {
		parts.pop();
	}
	parts.join("::")
}

/// Every non-test source file under `dir`, with its module path.
fn sources_under(dir: &Path, src: &Path, found: &mut Vec<(String, String)>) {
	let Ok(entries) = std::fs::read_dir(dir) else {
		return;
	};
	for entry in entries.flatten() {
		let path = entry.path();
		let name = entry.file_name().to_string_lossy().into_owned();
		if path.is_dir() {
			if name != "tests" {
				sources_under(&path, src, found);
			}
		} else if name.ends_with(".rs") && !is_test_file(&name) {
			let text = std::fs::read_to_string(&path).expect("read source");
			let code = without_test_module(&text);
			let relative = path.strip_prefix(src).expect("under src");
			found.push((module_of(relative), code));
		}
	}
}

fn protocol_sources() -> Vec<(String, String)> {
	let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
	let mut found = Vec::new();
	for dir in SCANNED_DIRS {
		sources_under(&src.join(dir), &src, &mut found);
	}
	for file in SCANNED_FILES {
		let text = std::fs::read_to_string(src.join(file)).expect("read source");
		found.push((module_of(Path::new(file)), text));
	}
	found
}

/// The lines of `text` that are not comments.
fn code_lines(text: &str) -> String {
	text.lines()
		.filter(|line| !line.trim_start().starts_with("//"))
		.collect::<Vec<_>>()
		.join("\n")
}

/// The `const NAME: <integer or Duration>` declarations of a file whose
/// name reads as a limit.
fn limit_constants(source: &str) -> Vec<&str> {
	source
		.lines()
		.filter_map(|line| {
			let line = line.trim_start();
			let line = ["pub(crate) ", "pub(super) ", "pub "]
				.iter()
				.find_map(|prefix| line.strip_prefix(prefix))
				.unwrap_or(line);
			let rest = line.strip_prefix("const ")?;
			let (name, ty) = rest.split_once(": ")?;
			let ty = ty.split(" =").next().unwrap_or(ty);
			let typed = ["usize", "u8", "u16", "u32", "u64", "i32", "i64", "u128"].contains(&ty)
				|| ty.ends_with("Duration");
			let limit = [
				"MAX_",
				"MIN_",
				"LIMIT",
				"TIMEOUT",
				"WINDOW",
				"_LEN",
				"_BYTES",
				"ITERATIONS",
				"_VALUES",
				"PER_LOOKUP",
			]
			.iter()
			.any(|word| name.contains(word));
			(typed && limit).then_some(name)
		})
		.collect()
}

/// The paths the rows read their values from, without `crate::`.
fn row_sources() -> BTreeSet<String> {
	catalog::FIXED
		.iter()
		.map(|row| row.source.trim_start_matches("crate::").to_string())
		.collect()
}

#[test]
fn every_limit_constant_in_the_protocol_modules_has_a_row() {
	let sources = row_sources();
	let mut unlisted = Vec::new();
	let mut seen = 0;
	for (module, code) in protocol_sources() {
		// A row may name a constant through the module that re-exports it.
		let parent = module
			.rsplit_once("::")
			.map(|(parent, _)| parent.to_string());
		for name in limit_constants(&code) {
			seen += 1;
			let listed = std::iter::once(&module)
				.chain(parent.as_ref())
				.any(|label| sources.contains(&format!("{label}::{name}")));
			let path = format!("{module}::{name}");
			let excused = NOT_A_ROW.iter().any(|(excused, _)| *excused == path);
			if !listed && !excused {
				unlisted.push(path);
			}
		}
	}
	assert!(seen > 50, "the scan found only {seen} limit constants");
	assert!(
		unlisted.is_empty(),
		"limits with no row in src/cli/limits/protocol.rs (add one, or name it in NOT_A_ROW with the reason): {unlisted:#?}"
	);
}

#[test]
fn every_row_names_a_constant_the_scan_finds() {
	let found: BTreeSet<String> = protocol_sources()
		.into_iter()
		.flat_map(|(module, code)| {
			let parent = module
				.rsplit_once("::")
				.map(|(parent, _)| parent.to_string());
			limit_constants(&code)
				.into_iter()
				.flat_map(|name| {
					std::iter::once(format!("{module}::{name}"))
						.chain(parent.iter().map(|parent| format!("{parent}::{name}")))
						.collect::<Vec<_>>()
				})
				.collect::<Vec<_>>()
		})
		.collect();
	for row in catalog::FIXED {
		if row.source.is_empty() || row.source.starts_with("tls::") {
			continue;
		}
		let source = row.source.trim_start_matches("crate::");
		assert!(
			found.contains(source),
			"row `{}` reads `{source}`, which no protocol module defines as a limit constant",
			row.name,
		);
	}
}

#[test]
fn every_excused_constant_still_exists_and_is_not_also_a_row() {
	let sources = protocol_sources();
	let rows = row_sources();
	let keys = code_lines(&format!(
		"{}{}{}",
		include_str!("mod.rs"),
		include_str!("keys.rs"),
		include_str!("catalog.rs")
	));
	for (path, reason) in NOT_A_ROW {
		assert!(!reason.is_empty(), "{path}: say why it is not a row");
		let found = sources.iter().any(|(module, code)| {
			limit_constants(code)
				.iter()
				.any(|name| format!("{module}::{name}") == *path)
		});
		assert!(
			found,
			"`{path}` is excused but no protocol module defines it any more"
		);
		assert!(!rows.contains(*path), "`{path}` is a row: drop the excuse");
		if reason.contains("adjustable") {
			let name = path.rsplit("::").next().unwrap();
			assert!(
				keys.contains(name),
				"`{path}` is said to back an adjustable key, but the key code never names it"
			);
		}
	}
}
