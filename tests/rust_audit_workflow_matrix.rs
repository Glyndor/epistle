//! Pin the pull_request branch of the rust-audit workflow matrix.
//!
//! On `pull_request` the workflow must audit the PR's own lockfile (a
//! single run on the PR head), not develop or main. A PR that adds a
//! vulnerable crate is the day the audit is most useful, and a matrix
//! over develop and main means the PR ships unchecked.
//!
//! The brief's chosen shape: an inline expression that yields `[""]`
//! on pull_request and `["develop","main"]` otherwise. This test pins
//! the two halves of that expression and refuses a literal `[develop,
//! main]` list that would skip the PR branch.

use std::fs;
use std::path::Path;

/// Pull the body of a YAML block whose key line is the only occurrence
/// at indent `n`. Mirrors the helper in `tests/rust_audit_workflow.rs`
/// so the two stay in sync.
fn extract_block(text: &str, key: &str) -> Option<String> {
	let mut in_block = false;
	let mut key_indent: usize = 0;
	let mut lines: Vec<&str> = Vec::new();
	for line in text.lines() {
		let trimmed = line.trim_start();
		if !in_block {
			if trimmed.starts_with(key) {
				in_block = true;
				key_indent = line.len() - trimmed.len();
			}
			continue;
		}
		if trimmed.is_empty() || trimmed.starts_with('#') {
			continue;
		}
		let line_indent = line.len() - trimmed.len();
		if line_indent <= key_indent {
			break;
		}
		lines.push(line);
	}
	if !in_block {
		return None;
	}
	Some(lines.join("\n"))
}

#[test]
fn rust_audit_matrix_audits_pr_head_when_event_is_pull_request() {
	let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(".github/workflows/rust-audit.yml");
	let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));

	let matrix_section = extract_block(&text, "matrix:")
		.unwrap_or_else(|| panic!("rust-audit.yml has no `strategy.matrix` for the audit matrix"));

	// The PR branch of the expression: `github.event_name == 'pull_request'`
	// gates an audit of just the PR head (empty ref -> checkout default).
	let triggers_pr = matrix_section.contains("github.event_name == 'pull_request'")
		&& matrix_section.contains("\"\"");
	assert!(
		triggers_pr,
		"rust-audit.yml matrix does not branch on pull_request with an empty ref.\n\
         On a pull_request the workflow must audit the PR's own lockfile; \
         the brief's chosen expression is `fromJSON(github.event_name == 'pull_request' && '[\"\"]' || '[\"develop\",\"main\"]')`. \
         A literal `[develop, main]` matrix would skip the PR branch and \
         a vulnerable bump could land without the workflow catching it.\n\
         Matrix section was:\n{matrix_section}",
	);

	// The non-PR branch: schedule and workflow_dispatch still audit
	// develop and main together, so a finding on either branch opens
	// an issue the day it appears.
	let has_dev = matrix_section.contains("develop");
	let has_main = matrix_section.contains("main");
	assert!(
		has_dev && has_main,
		"rust-audit.yml matrix is missing `develop` or `main` for the \
         schedule/workflow_dispatch branch.\n\
         Both branches carry their own audit graph; auditing only one is \
         the regression the 2026-09-28 incident was, on a smaller scale. \
         The expression must keep both refs in its non-PR half.\n\
         Matrix section was:\n{matrix_section}",
	);
}
