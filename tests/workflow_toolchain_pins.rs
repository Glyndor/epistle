//! Verify every `toolchain` pin declared in `.github/workflows/*.yml` agrees
//! with the others. A repository whose SBOM is produced by a compiler its
//! test suite never ran is the defect podup#1487 recorded — podup wrote a
//! test asserting its own two pins agree, and this one extends the same
//! invariant to every toolchain pin in this repository, so the supply-chain
//! job can never silently drift from the job whose code it ships.
//!
//! The test discovers the sites rather than enumerating them: a hardcoded
//! list goes stale the moment a fifth reusable gains an input `toolchain`,
//! which is the failure mode this guard exists to prevent. It also fails
//! when it finds fewer than four pins — an empty "all match" pass is the
//! false positive that podup#1487 was, and the count floor keeps the test
//! honest if a workflow is renamed or the YAML shape changes.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Minimum number of pins the test expects to find. Four sites exist today
/// (the three reusables' `toolchain` input defaults and `ci.yml`'s
/// `with.toolchain` override); the floor is the smallest count that
/// guarantees the test is actually walking the directory.
const MIN_PINS: usize = 4;

#[test]
fn workflow_toolchain_pins_agree() {
	let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join(".github/workflows");
	let mut entries: Vec<PathBuf> = fs::read_dir(&dir)
		.expect("read .github/workflows")
		.filter_map(Result::ok)
		.map(|e| e.path())
		.filter(|p| p.extension().is_some_and(|x| x == "yml"))
		.collect();
	entries.sort();

	let prefix = Path::new(env!("CARGO_MANIFEST_DIR"));
	let mut pins: Vec<(String, String)> = Vec::new();
	for path in &entries {
		let text =
			fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
		let rel = path
			.strip_prefix(prefix)
			.unwrap_or(path)
			.display()
			.to_string();
		for pin in extract_toolchain_pins(&text) {
			pins.push((rel.clone(), pin));
		}
	}

	assert!(
		pins.len() >= MIN_PINS,
		"expected at least {MIN_PINS} toolchain pins in .github/workflows/*.yml, found {}.\n\
		 The test discovers sites dynamically, so a smaller count usually means\n\
		 the YAML shape changed (a file moved, the input key was renamed,\n\
		 or `with.toolchain` lost its value). Inspect the directory.",
		pins.len()
	);

	let empty: Vec<&str> = pins
		.iter()
		.filter(|(_, v)| v.is_empty())
		.map(|(p, _)| p.as_str())
		.collect();
	assert!(
		empty.is_empty(),
		"toolchain key present but value is empty in: {}",
		empty.join(", ")
	);

	let mut by_value: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
	for (path, value) in &pins {
		by_value
			.entry(value.as_str())
			.or_default()
			.push(path.as_str());
	}
	if by_value.len() > 1 {
		let mut msg = String::from("toolchain pins disagree across .github/workflows/*.yml:\n");
		for (path, value) in &pins {
			msg.push_str(&format!("  {path} = {value:?}\n"));
		}
		msg.push_str("Bump or align them so every site declares the same value.");
		panic!("{msg}");
	}
}

/// Discover every `toolchain` pin declared in `text`. Two shapes count:
///
/// - An input default — the `toolchain:` key starts a block whose children
///   include a `default: <value>` line at one indent level deeper.
/// - A caller override — the `toolchain:` key carries its value inline
///   (`toolchain: "1.98"` inside a `with:` mapping).
///
/// `rust-toolchain:` and any other compound key are intentionally ignored;
/// `rust-toolchain` has different semantics and is declared in
/// `reusable-rust-debian.yml`.
fn extract_toolchain_pins(text: &str) -> Vec<String> {
	let mut out = Vec::new();
	let lines: Vec<&str> = text.lines().collect();
	for (i, line) in lines.iter().enumerate() {
		let trimmed = line.trim_start();
		if !trimmed.starts_with("toolchain:") {
			continue;
		}
		let after = trimmed.strip_prefix("toolchain:").unwrap().trim();
		if !after.is_empty() {
			out.push(unquote(strip_inline_comment(after)).to_string());
			continue;
		}
		let key_indent = line.len() - trimmed.len();
		for inner in &lines[i + 1..] {
			let inner_trimmed = inner.trim();
			if inner_trimmed.is_empty() || inner_trimmed.starts_with('#') {
				continue;
			}
			let inner_indent = inner.len() - inner.trim_start().len();
			if inner_indent <= key_indent {
				break;
			}
			if let Some(rest) = inner_trimmed.strip_prefix("default:") {
				let value = rest.trim();
				out.push(unquote(strip_inline_comment(value)).to_string());
				break;
			}
		}
	}
	out
}

/// Strip one matching pair of surrounding `"` or `'` from `s`, if present.
fn unquote(s: &str) -> &str {
	let bytes = s.as_bytes();
	if s.len() >= 2
		&& ((bytes[0] == b'"' && bytes[s.len() - 1] == b'"')
			|| (bytes[0] == b'\'' && bytes[s.len() - 1] == b'\''))
	{
		&s[1..s.len() - 1]
	} else {
		s
	}
}

/// Strip an inline YAML comment (` # ...`) from the end of `s`. A bare `#`
/// at the start is not a comment; an inline one must be preceded by whitespace.
fn strip_inline_comment(s: &str) -> &str {
	match s.find(" #") {
		Some(idx) => s[..idx].trim_end(),
		None => s,
	}
}
