//! Pin the label query used by the close job in rust-audit.yml.
//!
//! The old shape was a `tr ',' '%2C'` substitution into a `gh api`
//! URL: that maps characters, not strings, and the comma that should
//! have separated labels got encoded instead. The new shape is
//! `gh issue list --label ...` (repeated) plus `--json number --jq
//! '.[].number'`, which the `gh` wrapper applies as an AND over the
//! labels.
//!
//! This test greps the workflow file for the bad shape and the good
//! shape; both checks fail loudly if either regresses.

use std::fs;
use std::path::Path;

/// True when `text` contains `needle` on a line whose first non-space
/// character is not `#`. Mirrors the helper used elsewhere in this
/// directory so a commented-out snippet cannot satisfy the assertion.
fn contains_active(text: &str, needle: &str) -> bool {
	text.lines().any(|line| {
		let trimmed = line.trim_start();
		if trimmed.is_empty() || trimmed.starts_with('#') {
			return false;
		}
		trimmed.contains(needle)
	})
}

#[test]
fn rust_audit_close_uses_gh_issue_list_with_repeated_label_flags() {
	let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(".github/workflows/rust-audit.yml");
	let text = fs::read_to_string(&path)
		.unwrap_or_else(|e| panic!("read {}: {e}", path.display()));

	// The broken shape must be gone. `tr ',' '%2C'` is character-level,
	// not string-level, so the comma that should separate labels was
	// itself encoded and the API call returned the wrong set of issues.
	assert!(
		!contains_active(&text, "tr ',' '%2C'"),
		"rust-audit.yml still uses `tr ',' '%2C'` to build the label query.\n\
         `tr` maps characters, not strings, so the comma that should \
         separate labels was itself URL-encoded and the close job saw the \
         wrong set of issues. Use `gh issue list --label type:security --label \
         type:deps --label prio:P1 --label area:meta` (the `gh` wrapper \
         applies AND semantics over repeated `--label` flags).",
	);

	// The new shape must be present. The four labels must each appear
	// as a separate `--label` flag (a single comma-joined `--label` is
	// what the old call did and is exactly what we are replacing).
	for label in &["type:security", "type:deps", "prio:P1", "area:meta"] {
		let flag = format!("--label \"{label}\"");
		assert!(
			contains_active(&text, &flag),
			"rust-audit.yml close job does not carry `{flag}`.\n\
             The new lookup is `gh issue list --label type:security \
             --label type:deps --label prio:P1 --label area:meta`; each \
             label as a separate `--label` flag is what makes `gh` match \
             issues that carry all four.",
		);
	}

	// The narrow filter (`--json number --jq '.[].number'`) must be
	// present so the close loop iterates over a number list rather
	// than the full issue objects.
	assert!(
		contains_active(&text, "--json number")
			&& contains_active(&text, "--jq '.[].number'"),
		"rust-audit.yml close job does not narrow the issue list to numbers.\n\
         `gh issue list --json number --jq '.[].number'` is the filter \
         that turns the list of issue objects into one number per line \
         for the close loop. Without it the loop receives JSON, not \
         issue numbers.",
	);
}