//! Pin the `if:` guard on the report and close jobs in rust-audit.yml.
//!
//! Both jobs must skip `pull_request`. Today the close job's `if: success()`
//! would, on a green PR, close every still-open advisory issue this
//! workflow previously opened on develop/main. The report job's
//! `if: failure()` would, on a failing PR, open an issue that says
//! "develop and main have advisories" when in fact the PR alone does.
//! Neither belongs to the per-PR required check, only to the daily
//! cadence.

use std::fs;
use std::path::Path;

const REPORT_KEY: &str = "report:";
const CLOSE_KEY: &str = "close:";

/// Return the body of a job block whose `name:` line carries `key`.
/// Mirrors the helper in `tests/workflows/audit/rust_audit_workflow.rs` so they
/// stay in sync. The block ends at the next job (`^  [a-z][a-z0-9_]*:$`
/// at the same indent) or at any shallower indent.
fn extract_job_block(text: &str, key: &str) -> Option<String> {
	let mut in_block = false;
	let mut key_indent: usize = 0;
	let mut lines: Vec<&str> = Vec::new();
	for line in text.lines() {
		let trimmed = line.trim_start();
		if !in_block {
			if trimmed == key {
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

/// True when `block` has an `if:` line that mentions both `failure()`
/// (or `success()` for the close job) and `github.event_name != 'pull_request'`.
fn guard_skips_pull_request(block: &str, want_outcome: &str) -> bool {
	for line in block.lines() {
		let trimmed = line.trim_start();
		if trimmed.is_empty() || trimmed.starts_with('#') {
			continue;
		}
		if !trimmed.starts_with("if:") {
			continue;
		}
		let after = trimmed.strip_prefix("if:").unwrap().trim();
		if after.contains(want_outcome) && after.contains("github.event_name != 'pull_request'") {
			return true;
		}
	}
	false
}

#[test]
fn rust_audit_report_and_close_skip_on_pull_request() {
	let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(".github/workflows/rust-audit.yml");
	let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));

	let report = extract_job_block(&text, REPORT_KEY)
		.unwrap_or_else(|| panic!("rust-audit.yml has no `report:` job"));
	let close = extract_job_block(&text, CLOSE_KEY)
		.unwrap_or_else(|| panic!("rust-audit.yml has no `close:` job"));

	assert!(
		guard_skips_pull_request(&report, "failure()"),
		"rust-audit.yml `report:` job does not skip pull_request.\n\
         Without the guard, a failing PR opens an issue owned by this \
         workflow that is really about the PR alone. The per-PR required \
         check has no need to open an issue; the open-issue behaviour \
         belongs to the daily cadence. The `if:` must combine the failure \
         check with `github.event_name != 'pull_request'`.\n\
         Job block was:\n{report}",
	);

	assert!(
		guard_skips_pull_request(&close, "success()"),
		"rust-audit.yml `close:` job does not skip pull_request.\n\
         Without the guard, a green PR closes every still-open advisory \
         issue this workflow opened on develop/main. The close signal \
         belongs to the daily cadence; the per-PR required check should \
         never touch open issues.\n\
         Job block was:\n{close}",
	);
}
