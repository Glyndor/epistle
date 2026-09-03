//! Verify the UTC invariant epistle relies on by absence.
//!
//! The server stamps every wall-clock value from [`std::time::SystemTime`]
//! and the few formatters in [`crate::clock`] hard-code `+0000`. Nothing
//! here needs a zone database, and the absence of one is what makes it
//! impossible for the server to disagree with itself about which timezone
//! `2026-06-05 12:34:56` lives in.
//!
//! That property holds by absence. The first PR that adds a timezone-aware
//! dependency — or the first call to `Local::now()` somewhere in `src/` —
//! breaks it, and the breakage is silent: header formatters, DKIM
//! signature timestamps, audit logs, and any other consumer that depends
//! on a stable UTC stamp all start mixing local and UTC values without
//! any test in the production suite catching the regression.
//!
//! Two checks guard the invariant, both inspecting the repository rather
//! than the code:
//!
//! - `Cargo.toml` does not declare a timezone-aware crate (`chrono`,
//!   `time`, or `jiff`). Each of these carries, or transitively pulls
//!   in, a zone database and exposes APIs that turn a `SystemTime`
//!   into a local-time value without an explicit operator choice.
//!   `Cargo.lock` is not checked: it is regenerated on every build and a
//!   transitive entry would already be visible in the manifest as soon
//!   as it is needed by a direct dependency.
//! - `src/**/*.rs` does not call `Local::now()` / `Local::today()` or
//!   refer to `chrono::Local` / `time::OffsetDateTime::now_local`.
//!   These are the calls that turn the absence into a presence.
//!
//! The minimum-file floor is the analogue of the
//! `expected at least N toolchain pins` check in
//! `tests/workflow_toolchain_pins.rs`: a regex that never matches is the
//! same green as a regex that does match and finds nothing, so the test
//! would silently pass even if the pattern were broken or the directory
//! moved. The floor forces the test to actually walk the tree and find
//! the file it is meant to inspect.
//!
//! Provenance: this test fails when expected. Adding `chrono = "0.4"`
//! to `Cargo.toml` makes `cargo test --test utc_purity` report the
//! expected failure; the same change to `src/` makes it fail with the
//! offending line reported.

use std::fs;
use std::path::{Path, PathBuf};

/// Crate names whose presence in `Cargo.toml` would silently re-introduce
/// a zone database. Names match a TOML dependency line, so the value can
/// be any of the supported shapes (`"0.4"`, `{ version = "...", ... }`).
const FORBIDDEN_CRATES: &[&str] = &["chrono", "time", "jiff"];

/// Substrings that mark a `Local::` style call in `src/`. Anything that
/// reaches for a local-time value falls in this set; the corresponding
/// UTC call is `SystemTime::now()` plus a `clock::rfc5322` /
/// `clock::rfc3339` formatter.
const FORBIDDEN_CALLS: &[&str] = &[
	"Local::now(",
	"Local::today(",
	"Local::yesterday(",
	"chrono::Local",
	"time::OffsetDateTime::now_local",
	"jiff::Zoned::now(",
];

/// Minimum number of `.rs` files the test expects to find under `src/`.
/// The clock, metrics and totp modules alone give us this many, and a
/// future crate shrink below this number is itself a signal worth
/// investigating.
const MIN_SOURCE_FILES: usize = 30;

#[test]
fn cargo_manifest_declares_no_timezone_aware_crate() {
	let manifest_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
	let manifest = fs::read_to_string(&manifest_path).expect("read Cargo.toml");

	let mut offenders: Vec<(&str, String)> = Vec::new();
	for line in manifest.lines() {
		let trimmed = line.trim_start();
		if trimmed.starts_with('#') {
			continue;
		}
		for crate_name in FORBIDDEN_CRATES {
			// Match `<name> =` with optional whitespace. A line like
			// `not-chrono = "1"` would match a naive substring search;
			// anchoring the name to the start of the LHS of an `=`
			// forbids that false positive without complicating the
			// pattern.
			if line_starts_with_dep(line, crate_name) {
				offenders.push((crate_name, line.to_string()));
			}
		}
	}

	assert!(
		offenders.is_empty(),
		"Cargo.toml declares a timezone-aware crate; epistle stamps UTC from \
		 SystemTime and must not carry a zone database. Offending lines:\n  {}",
		offenders
			.iter()
			.map(|(_, line)| line.as_str())
			.collect::<Vec<_>>()
			.join("\n  ")
	);
}

/// `src/**/*.rs` contains no `Local::now()` or equivalent. The call site
/// is reported in the failure message so the operator can fix the
/// offending line without re-reading the pattern.
#[test]
fn src_has_no_local_now_or_equivalent_call() {
	let root = Path::new(env!("CARGO_MANIFEST_DIR"));
	let src = root.join("src");
	let files = collect_rs_files(&src);
	assert!(
		files.len() >= MIN_SOURCE_FILES,
		"expected at least {MIN_SOURCE_FILES} .rs files under {}, found {}. \
		 The minimum is the analogue of the pin floor in \
		 tests/workflow_toolchain_pins.rs: a regex that never matches is the \
		 same green as a regex that matches nothing, so this floor forces \
		 the test to actually walk the source tree.",
		files.len(),
		src.display()
	);

	let mut offenders: Vec<(PathBuf, usize, String)> = Vec::new();
	for path in &files {
		let text = fs::read_to_string(path).unwrap_or_default();
		for (idx, line) in text.lines().enumerate() {
			let trimmed = line.trim_start();
			// Skip comments and string literals that mention the
			// function name only to describe it (e.g. the doc comment
			// above this very test). Anything left is a real call.
			if trimmed.starts_with("//") {
				continue;
			}
			for forbidden in FORBIDDEN_CALLS {
				if line.contains(forbidden) {
					offenders.push((path.clone(), idx + 1, line.to_string()));
				}
			}
		}
	}

	assert!(
		offenders.is_empty(),
		"src/ contains a timezone-aware call; use SystemTime::now() and the \
		 UTC formatters in crate::clock instead. Offending lines:\n{}",
		offenders
			.iter()
			.map(|(path, line, text)| format!(
				"  {}:{}  {}",
				path.strip_prefix(root).unwrap_or(path).display(),
				line,
				text
			))
			.collect::<Vec<_>>()
			.join("\n")
	);
}

/// Collect every `.rs` file under `dir` in deterministic order. The walk
/// is non-recursive on directories starting with `.` (e.g. `.git`),
/// which are not part of the source tree the test is meant to inspect.
fn collect_rs_files(dir: &Path) -> Vec<PathBuf> {
	let mut out = Vec::new();
	walk(dir, &mut out);
	out.sort();
	out
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
	let Ok(entries) = fs::read_dir(dir) else {
		return;
	};
	for entry in entries.flatten() {
		let path = entry.path();
		let name = entry.file_name();
		if name.to_string_lossy().starts_with('.') {
			continue;
		}
		if path.is_dir() {
			walk(&path, out);
		} else if path.extension().is_some_and(|e| e == "rs") {
			out.push(path);
		}
	}
}

/// True when `line` declares a top-level dependency named `crate_name`.
/// The line is trimmed first so leading whitespace does not push the
/// regex past the LHS of the `=`; a comment (`#`) prefix is handled by
/// the caller.
fn line_starts_with_dep(line: &str, crate_name: &str) -> bool {
	let trimmed = line.trim_start();
	let Some(after) = trimmed.strip_prefix(crate_name) else {
		return false;
	};
	// Must be followed by whitespace, then `=`. The whitespace is what
	// disambiguates `chrono` from a hypothetical `chrono_extra` crate;
	// the `=` is what distinguishes a dependency line from a section
	// header like `[patch.crates-io]` or a key in a `[features]` table.
	let mut chars = after.chars();
	match chars.next() {
		Some(c) if c.is_whitespace() => {}
		_ => return false,
	}
	chars.next() == Some('=')
}
