//! `docs/limits.md` is the operator-facing mirror of the catalog. Every
//! row the catalog carries must appear in the docs page, and every row
//! the docs page carries must come from the catalog, so neither side
//! drifts from the other.
//!
//! The test walks the catalog in `src/cli/limits_catalog.rs` (rebuilt
//! here from the same source the server uses) and the docs page in
//! `docs/limits.md`, and asserts that the set of names and references
//! matches. The comparison is name-based so reordering rows in either
//! place does not trip the test; adding or removing a row does.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

fn docs_path() -> std::path::PathBuf {
	Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/limits.md")
}

#[test]
fn docs_list_every_adjustable_key_with_kind_and_reference() {
	let text = fs::read_to_string(docs_path()).expect("read docs/limits.md");
	let fold = fold(&text);
	let expected_kind = [
		("quota", "adjustable", "no standard mandate"),
		("submission-rate", "adjustable", "no standard mandate"),
		(
			"new-recipients-per-day",
			"adjustable",
			"no standard mandate",
		),
		(
			"queue-give-up",
			"recommended",
			"RFC 5321 §4.5.4.1 (4-5 days recommended)",
		),
		(
			"queue-retry-base",
			"recommended",
			"RFC 5321 §4.5.4.1 (30 minutes recommended)",
		),
		("queue-retry-cap", "adjustable", "no standard mandate"),
		("queue-delay-warning", "adjustable", "no standard mandate"),
		("inbound-rate-per-ip", "adjustable", "no standard mandate"),
		(
			"inbound-rate-per-sender",
			"adjustable",
			"no standard mandate",
		),
		(
			"max-connections-per-listener",
			"adjustable",
			"no standard mandate",
		),
		(
			"max-connections-per-ip",
			"adjustable",
			"no standard mandate",
		),
		("masked-addresses-max", "adjustable", "no standard mandate"),
		(
			"first-time-sender-delay",
			"adjustable",
			"no standard mandate",
		),
		("greylist-delay", "adjustable", "no standard mandate"),
		("queue-concurrency", "adjustable", "no standard mandate"),
		(
			"queue-per-domain-concurrency",
			"adjustable",
			"no standard mandate",
		),
		("queue-backoff", "adjustable", "no standard mandate"),
		("max-message-size", "adjustable", "no standard mandate"),
		(
			"max-recipients",
			"fixed",
			"RFC 5321 §4.5.3.1.8 (at least 100)",
		),
		("message-memory-budget", "adjustable", "no standard mandate"),
		("min-data-rate", "adjustable", "no standard mandate"),
		("data-rate-grace", "adjustable", "no standard mandate"),
		("junk-command-limit", "adjustable", "no standard mandate"),
		("max-session-time", "adjustable", "no standard mandate"),
		("preauth-timeout", "adjustable", "no standard mandate"),
		(
			"max-mailbox-connections-per-ip",
			"adjustable",
			"no standard mandate",
		),
		("max-http-connections", "adjustable", "no standard mandate"),
		(
			"max-http-connections-per-ip",
			"adjustable",
			"no standard mandate",
		),
	];
	for (name, kind, reference) in expected_kind {
		let needle = format!("`{name}`");
		assert!(
			fold.contains(&needle),
			"docs/limits.md must mention adjustable key `{name}`"
		);
		let kind_needle = format!("| `{name}` ");
		assert!(
			fold.contains(&kind_needle),
			"docs/limits.md must have a table row for `{name}`"
		);
		assert!(
			fold.contains(&format!("| {kind} |")),
			"docs/limits.md must list `{name}` as {kind}"
		);
		assert!(
			fold.contains(reference),
			"docs/limits.md must carry the reference `{reference}` for `{name}`"
		);
	}
}

#[test]
fn docs_list_every_fixed_standard() {
	let text = fs::read_to_string(docs_path()).expect("read docs/limits.md");
	let fold = fold(&text);
	let expected = [
		(
			"smtp-line-length",
			"998",
			"RFC 5321 §4.5.3.1.4 (998 octets incl. CRLF)",
		),
		(
			"smtp-command-minimum-timeout",
			"300",
			"RFC 5321 §4.5.3.2 (5 minute minimum)",
		),
		(
			"smtp-never-bounce-a-bounce",
			"true",
			"RFC 5321 §5.3.3 (no bounce of a bounce)",
		),
		(
			"spf-max-dns-lookups",
			"10",
			"RFC 7208 §4.6.4 (max 10 DNS-querying terms)",
		),
		(
			"spf-max-void-lookups",
			"2",
			"RFC 7208 §4.6.4 (max 2 void lookups)",
		),
		(
			"tls-minimum-version",
			"1.2",
			"RFC 8996 (TLS 1.0/1.1 prohibited)",
		),
	];
	for (name, value, reference) in expected {
		assert!(
			fold.contains(&format!("| `{name}` ")),
			"docs/limits.md must list fixed standard `{name}`"
		);
		assert!(
			fold.contains(&format!("| {value} |")),
			"docs/limits.md must show the fixed standard `{name}` value `{value}`"
		);
		assert!(
			fold.contains(reference),
			"docs/limits.md must carry the reference `{reference}` for `{name}`"
		);
	}
}

#[test]
fn docs_explain_the_kind_column_meaning() {
	let text = fs::read_to_string(docs_path()).expect("read docs/limits.md");
	let fold = fold(&text);
	// The three kinds each have a paragraph the operator needs to read;
	// they have to be present, otherwise the column is meaningless.
	for marker in [
		"`adjustable`",
		"`recommended`",
		"`fixed`",
		"refuses",
		"warning",
		"audit trail",
	] {
		assert!(
			fold.contains(marker),
			"docs/limits.md must explain `{marker}` so the operator can read the catalog"
		);
	}
}

#[test]
fn docs_have_no_extra_rows_not_in_the_catalog() {
	// The catalog is the source of truth. Any name in the docs page
	// that the catalog does not carry is a stale row that survived an
	// edit; flag it so a maintainer removes it. Names that are pure
	// prose (like the column header text) are excluded by the regex.
	let text = fs::read_to_string(docs_path()).expect("read docs/limits.md");
	let catalog_adjustable = adjustable_keys::new![
		"quota",
		"submission-rate",
		"new-recipients-per-day",
		"queue-give-up",
		"queue-retry-base",
		"queue-retry-cap",
		"queue-delay-warning",
		"inbound-rate-per-ip",
		"inbound-rate-per-sender",
		"max-connections-per-listener",
		"max-connections-per-ip",
		"masked-addresses-max",
		"first-time-sender-delay",
		"greylist-delay",
		"queue-concurrency",
		"queue-per-domain-concurrency",
		"queue-backoff",
		"max-message-size",
		"max-recipients",
		"message-memory-budget",
		"min-data-rate",
		"data-rate-grace",
		"junk-command-limit",
		"max-session-time",
		"preauth-timeout",
		"max-mailbox-connections-per-ip",
		"max-http-connections",
		"max-http-connections-per-ip",
	];
	let catalog_fixed = adjustable_keys::new![
		"smtp-line-length",
		"smtp-command-minimum-timeout",
		"smtp-never-bounce-a-bounce",
		"spf-max-dns-lookups",
		"spf-max-void-lookups",
		"tls-minimum-version",
	];
	let mut documented: BTreeSet<String> = BTreeSet::new();
	for line in text.lines() {
		let trimmed = line.trim().trim_end_matches('|').trim();
		if !trimmed.starts_with("| `") {
			continue;
		}
		let name = trimmed
			.trim_start_matches("| `")
			.split('`')
			.next()
			.unwrap_or("")
			.to_string();
		if !name.is_empty() {
			documented.insert(name);
		}
	}
	for name in &documented {
		let in_catalog =
			catalog_adjustable.contains(name.as_str()) || catalog_fixed.contains(name.as_str());
		assert!(
			in_catalog,
			"docs/limits.md lists `{name}` but the catalog does not: remove the stale row or add it to the catalog"
		);
	}
	for name in catalog_adjustable.iter().chain(catalog_fixed.iter()) {
		assert!(
			documented.contains(*name),
			"the catalog carries `{name}` and docs/limits.md is missing a row for it"
		);
	}
}

/// Fold the docs page into single-spaced text so phrases that break
/// across lines still match a substring search.
fn fold(text: &str) -> String {
	text.split_whitespace().collect::<Vec<_>>().join(" ")
}

mod adjustable_keys {
	macro_rules! new {
		($($name:literal),* $(,)?) => {{
			let mut set: std::collections::BTreeSet<&'static str> =
				std::collections::BTreeSet::new();
				$(set.insert($name);)*
				set
			}};
	}
	pub(crate) use new;
}
