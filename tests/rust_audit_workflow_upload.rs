//! Pin the upload step in `.github/workflows/reusable-rust-audit.yml`.
//!
//! The "Upload cargo audit JSON" step must run even when the audit
//! failed, so the report job can still read the JSON and decide whether
//! to open an issue. A bare step with no `if:` is `if: success()`, so a
//! failed audit silently drops the artifact and the report job finds
//! nothing. The same rule applies to the extra-lockfile (fuzz) audit:
//! its JSON has to be in the artifact the report job downloads.
//!
//! This test reads the workflow as text and grep-extracts the upload
//! step block, then asserts:
//!
//! 1. The step carries `if: always()` so a failed audit still uploads.
//! 2. The `path:` globs `audit-*.json`, which covers the name the
//!    extra-lockfile step derives from its input path
//!    (`audit-fuzz-Cargo.json` for `fuzz/Cargo.lock`). The name has to be
//!    derived from the whole path, not from the file's base name, so two
//!    workspaces cannot land on the same report.

use std::fs;
use std::path::Path;

/// Pull the body of a step block from the workflow file. The key
/// (`- name:`) starts the block; the block ends at the first sibling
/// step (another `- name:` at the same indent) or at a shallower
/// indent. Comment lines and blank lines are dropped so a commented-out
/// `- name:` cannot be confused with an active one.
fn extract_step(text: &str, step_name: &str) -> Option<String> {
	let mut in_step = false;
	let mut step_indent: usize = 0;
	let mut lines: Vec<&str> = Vec::new();
	for line in text.lines() {
		let trimmed = line.trim_start();
		if !in_step {
			if trimmed.starts_with("- name: ") && trimmed.contains(step_name) {
				in_step = true;
				step_indent = line.len() - trimmed.len();
			}
			continue;
		}
		if trimmed.is_empty() || trimmed.starts_with('#') {
			continue;
		}
		let line_indent = line.len() - trimmed.len();
		// Sibling step at the same indent ends the block.
		if line_indent == step_indent && trimmed.starts_with("- ") {
			break;
		}
		if line_indent < step_indent {
			break;
		}
		lines.push(line);
	}
	if !in_step {
		return None;
	}
	Some(lines.join("\n"))
}

#[test]
fn reusable_audit_uploads_json_unconditionally_and_includes_fuzz() {
	let path =
		Path::new(env!("CARGO_MANIFEST_DIR")).join(".github/workflows/reusable-rust-audit.yml");
	let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));

	let step = extract_step(&text, "Upload cargo audit JSON")
		.unwrap_or_else(|| panic!("reusable-rust-audit.yml has no `Upload cargo audit JSON` step"));

	assert!(
		step.contains("always()"),
		"reusable-rust-audit.yml `Upload cargo audit JSON` step has no `always()` guard.\n\
         A bare step defaults to `if: success()`, so a failing audit never \
         uploads its JSON and the report job has nothing to read. The step \
         must be `if: always() && hashFiles(...)` so the artifact still \
         ships when the audit failed.\nStep block was:\n{step}",
	);

	assert!(
		step.contains("audit-*.json"),
		"reusable-rust-audit.yml `Upload cargo audit JSON` step does not list the \
         `audit-*.json` glob in its `path:`.\n\
         The extra-lockfile audit writes one report per workspace, named after the \
         lockfile path (`fuzz/Cargo.lock` -> `audit-fuzz-Cargo.json`); without a glob \
         the upload lists one hardcoded name and a second workspace is invisible to \
         the report job.\n\
         Step block was:\n{step}",
	);
}
