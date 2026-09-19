//! Pin the regex used by the coverage gate to drop every test file
//! cargo llvm-cov would otherwise count. The whole point of
//! `coverage-ignore-regex` is the literal alternation it stores, so the test
//! reads the YAML, extracts the value, and asserts on it.
//!
//! Why no behavioural match/no-match check: the `regex` crate is not a
//! dependency and splitting the alternation by hand would let a future
//! edit drift the test away from the YAML without anyone noticing. The
//! fragments below are the three halves of the alternation that
//! `coverage-ignore-regex` must carry; their presence in the YAML value is
//! what guarantees the gate covers the test files. A future PR that adds
//! the `regex` crate as a dev-dependency can grow this into a true
//! match/no-match check that asserts, for example, that the regex matches
//! `src/api/jmap_tests_b.rs`, `src/cli/init/apply_tests_b.rs`,
//! `src/cli/local/test_support.rs` and `src/foo_tests.rs`, and does NOT
//! match `src/smtp/server/run.rs`, `src/antispam/subjectpass.rs` or
//! `src/cli/config_check.rs`. Until then the substring assertion is the
//! strongest one available without pulling in a new dependency.
//!
//! Two extra families of split test files exist beyond the simple
//! `*_tests_b.rs` / `*_tests_<letter>.rs` shape:
//! `*_tests_<multi-word>.rs` (e.g. `jmap_tests_encoded_words.rs`, where
//! `[a-z0-9]+` stops at the inner underscore) and `tests_*.rs` under
//! `dns/namecheap/` (e.g. `tests_basic.rs`, where the filename lacks the
//! leading underscore `_tests` would expect). The alternation below
//! extends the simpler form to cover both: `_tests(_[a-z0-9_]+)?` for the
//! underscore-named companions and `tests_[a-z0-9_]+` as a third
//! alternation for the namecheap tests.

use std::fs;
use std::path::Path;

/// The three halves of the alternation that
/// `coverage-ignore-regex` must carry to drop every test file. The literal
/// `\\.rs` at the end of the YAML scalar is the shared file-extension anchor
/// the regex needs, and is checked separately so a typo on the anchor itself
/// still trips the test.
const TEST_FILE_FRAGMENTS: &[&str] = &[
	// Covers *_tests_b.rs, *_tests_c.rs, ..., *_tests_<word>.rs.
	r"_tests(_[a-z0-9_]+)?",
	// Covers cli/local/test_support.rs, dns/gcloud_test_support.rs and
	// smtp/directory_test_support.rs.
	r"test_support",
	// Covers dns/namecheap/tests_basic.rs, dns/namecheap/tests_errors.rs
	// and dns/namecheap/tests_render.rs.
	r"tests_[a-z0-9_]+",
];

/// The shared file-extension anchor at the end of the alternation. Written as
/// the YAML escape (`\\.rs`) rather than the regex form (`\.rs`) because the
/// test asserts on the literal characters that appear in the YAML scalar.
const FILE_EXTENSION_ANCHOR: &str = r"\\.rs";

#[test]
fn coverage_ignore_regex_drops_every_test_file() {
	let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(".github/workflows/ci.yml");
	let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));

	let value = extract_value(&text, "coverage-ignore-regex")
		.unwrap_or_else(|| panic!("coverage-ignore-regex not found in {}", path.display()));

	for fragment in TEST_FILE_FRAGMENTS {
		assert!(
			value.contains(fragment),
			"coverage-ignore-regex is missing the fragment {:?}.\n\
			 The gate needs it to leave test files out of the coverage number.\n\
			 Current value: {value:?}",
			fragment,
		);
	}
	assert!(
		value.ends_with(FILE_EXTENSION_ANCHOR),
		"coverage-ignore-regex does not end with {:?}; without that anchor the \
		 alternation matches paths by accident rather than by file extension.\n\
		 Current value: {value:?}",
		FILE_EXTENSION_ANCHOR,
	);
}

/// Read `coverage-ignore-regex:` out of `text` as a raw YAML scalar. The value
/// is written as a double-quoted YAML string, so the function strips one
/// matching pair of `"` and returns the body untouched: any `\\.` escape
/// stays as `\\.` because the test asserts on the literal characters that
/// appear in the YAML, not on the regex the engine compiles.
fn extract_value(text: &str, key: &str) -> Option<String> {
	for line in text.lines() {
		let trimmed = line.trim_start();
		let prefix = format!("{key}:");
		let Some(after) = trimmed.strip_prefix(&prefix) else {
			continue;
		};
		let after = after.trim();
		return Some(strip_matching_quotes(after));
	}
	None
}

fn strip_matching_quotes(s: &str) -> String {
	let bytes = s.as_bytes();
	if s.len() >= 2 && bytes[0] == bytes[s.len() - 1] && (bytes[0] == b'"' || bytes[0] == b'\'') {
		s[1..s.len() - 1].to_string()
	} else {
		s.to_string()
	}
}

#[test]
fn coverage_threshold_is_ratcheted_below_the_pre_split_total() {
	let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(".github/workflows/ci.yml");
	let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));

	let threshold = extract_threshold(&text)
		.unwrap_or_else(|| panic!("coverage-threshold not found in {}", path.display()));
	let threshold: u32 = threshold
		.parse()
		.unwrap_or_else(|e| panic!("coverage-threshold {threshold:?} is not a number: {e}"));

	assert!(
		threshold <= 90,
		"coverage-threshold is {threshold}, above the pre-split 90. The gate \
		 used to count test files as covered production code; lifting the \
		 threshold back to that era is the regression issue #921 prevents.",
	);
}

/// Read `coverage-threshold:` out of `text` as a plain integer. The value is a
/// bare number in YAML, so a `trim()` and a `parse` is enough.
fn extract_threshold(text: &str) -> Option<String> {
	for line in text.lines() {
		let trimmed = line.trim_start();
		let Some(after) = trimmed.strip_prefix("coverage-threshold:") else {
			continue;
		};
		let value = after.trim();
		if !value.is_empty() {
			return Some(value.to_string());
		}
	}
	None
}
