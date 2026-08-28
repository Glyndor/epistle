//! Verify every toolchain pin declared in `.github/workflows/*.yml` agrees
//! with the others. Two shapes count:
//!
//! - The `toolchain:` input key, a default under `on.workflow_call.inputs`
//!   or an override under `with.toolchain` in a caller.
//! - `rustup toolchain install <value>` (followed by `rustup default <value>`
//!   with the same value) in a job step. The reusable workflows use
//!   `$TOOLCHAIN` / `$MSRV` here, which is not a concrete pin and so is
//!   skipped; the concrete value they install is captured by the `toolchain:`
//!   key scan.
//!
//! A repository whose SBOM is produced by a compiler its test suite never
//! ran is podup#1487, and "all toolchain pins say 1.98" was true here only
//! while the test looked at the four reusable defaults. Six `stable`
//! installs in jobs that build the criterion target, exercise Postgres,
//! run the real binary end-to-end, exercise protocol interop and run
//! cargo-mutants were floating to whatever `stable` was that day, and
//! the previous version of this test walked past them.
//!
//! The test discovers the sites rather than enumerating them: a hardcoded
//! list goes stale the moment a fifth reusable gains an input `toolchain`,
//! which is the failure mode this guard exists to prevent. It also fails
//! when it finds fewer than twelve pins: an empty "all match" pass is the
//! false positive that podup#1487 was, and the count floor keeps the test
//! honest if a workflow is renamed or the YAML shape changes.
//!
//! Pin values are compared after stripping a trailing `.0` so `1.98` and
//! `1.98.0` agree: they are the same compiler written two ways. `1.98`
//! and `1.98.1` do not agree, same major.minor but a different patch.
//! `nightly` is exempt by value (not by file name): fuzzing requires it
//! and pinning it to a date would defeat the point, but exempting it by
//! value rather than by file keeps the rule visible if some other site
//! starts using nightly.
//!
//! `rust-toolchain:` and any other compound key are intentionally ignored;
//! `rust-toolchain` has different semantics and is declared in
//! `reusable-rust-debian.yml`.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Minimum number of pins the test expects to find. Twelve sites exist
/// today (the three reusables' `toolchain` input defaults, `ci.yml`'s
/// `with.toolchain` override, two `rustup toolchain install 1.98.0` lines
/// in `release.yml`, and six `rustup toolchain install 1.98` lines
/// across the bench, db, e2e, interop and mutants workflows); the floor
/// is the smallest count that guarantees the test is actually walking
/// the directory and finding both pin shapes.
const MIN_PINS: usize = 12;

/// Which YAML shape a pin was discovered from. Reported in the failure
/// message because the fix is different: a key pin is an input default or
/// override (one place), a `rustup` pin is two adjacent `install` /
/// `default` lines (another).
#[derive(Clone, Copy)]
enum PinForm {
	Key,
	Rustup,
}

impl PinForm {
	fn as_str(self) -> &'static str {
		match self {
			PinForm::Key => "key",
			PinForm::Rustup => "rustup",
		}
	}
}

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
	let mut pins: Vec<(String, String, PinForm)> = Vec::new();
	for path in &entries {
		let text =
			fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
		let rel = path
			.strip_prefix(prefix)
			.unwrap_or(path)
			.display()
			.to_string();
		for pin in extract_toolchain_pins(&text) {
			pins.push((rel.clone(), pin, PinForm::Key));
		}
		for pin in extract_rustup_install_pins(&text) {
			pins.push((rel.clone(), pin, PinForm::Rustup));
		}
	}

	assert!(
		pins.len() >= MIN_PINS,
		"expected at least {MIN_PINS} toolchain pins in .github/workflows/*.yml, found {}.\n\
		 The test discovers sites dynamically, so a smaller count usually means\n\
		 the YAML shape changed (a file moved, the input key was renamed,\n\
		 `with.toolchain` lost its value, or `rustup toolchain install` was\n\
		 rewritten). Inspect the directory.",
		pins.len()
	);

	let empty: Vec<&str> = pins
		.iter()
		.filter(|(_, v, _)| v.is_empty())
		.map(|(p, _, _)| p.as_str())
		.collect();
	assert!(
		empty.is_empty(),
		"toolchain pin present but value is empty in: {}",
		empty.join(", ")
	);

	// Exempt `nightly` by value, not by file. fuzz.yml is the only site
	// using it today, and fuzzing requires nightly (cargo-fuzz needs the
	// nightly-only ` Arbitrary` derive). Exempting by value keeps the rule
	// visible: any other site that starts installing nightly trips the
	// test, and a comment on this branch explains the one site that does
	// not.
	let pins: Vec<(String, String, PinForm)> = pins
		.into_iter()
		.filter(|(_, v, _)| v != "nightly")
		.collect();

	let mut by_value: BTreeMap<String, Vec<(String, String, PinForm)>> = BTreeMap::new();
	for (path, value, form) in &pins {
		by_value
			.entry(normalize(value))
			.or_default()
			.push((path.clone(), value.clone(), *form));
	}
	if by_value.len() > 1 {
		let mut msg = String::from("toolchain pins disagree across .github/workflows/*.yml:\n");
		for (path, value, form) in &pins {
			msg.push_str(&format!(
				"  {path} ({form}) = {value:?}\n",
				form = form.as_str()
			));
		}
		msg.push_str(
			"Bump or align them so every site declares the same value. Pin values are \
			 compared after stripping a trailing `.0`, so `1.98` and `1.98.0` already agree.",
		);
		panic!("{msg}");
	}
}

/// Normalize a pin value for comparison. Strips a single trailing `.0` so
/// the bare-major-minor form (`1.98`) and the explicit-patch form
/// (`1.98.0`) match: the same rustc release written differently. Does not
/// touch `1.98.1` (different patch, not the same compiler) or anything
/// else (`stable`, `nightly`, `beta`).
fn normalize(value: &str) -> String {
	match value.strip_suffix(".0") {
		Some(stripped) => stripped.to_string(),
		None => value.to_string(),
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

/// Discover every `rustup toolchain install <value>` site in `text`. The
/// value is the first whitespace-delimited token after `install ` and is
/// assumed to be followed by a matching `rustup default <value>` line
/// with the same value (the install command sets the default on first
/// use, the default line is a redundant assert; both are present in
/// every concrete-pin site today).
///
/// Variable references (`$TOOLCHAIN`, `$MSRV`) used by the reusable
/// workflows are skipped: they are not concrete pins, the concrete value
/// they install is already captured by the `toolchain:` key scan.
fn extract_rustup_install_pins(text: &str) -> Vec<String> {
	let mut out = Vec::new();
	for line in text.lines() {
		let trimmed = line.trim_start();
		let after = match trimmed.strip_prefix("rustup toolchain install ") {
			Some(s) => s,
			None => continue,
		};
		let raw = match after.split_whitespace().next() {
			Some(v) => v,
			None => continue,
		};
		let value = unquote(strip_inline_comment(raw));
		// Skip if the value is a variable reference (e.g. `"$TOOLCHAIN"`),
		// not a concrete pin. The reusable workflows propagate these from
		// their `toolchain` input, and the concrete value is captured by
		// the `toolchain:` key scan above.
		if value.is_empty() || value.starts_with('#') || value.starts_with('$') {
			continue;
		}
		out.push(value.to_string());
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
