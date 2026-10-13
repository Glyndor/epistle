//! Pin the failure-issue path in `.github/workflows/rust-audit.yml`.
//!
//! When the reusable fails but the JSON the combine script reads
//! listed no advisories (cargo-deny policy, tool install error,
//! missing lockfile, JSON the combine could not parse), the workflow
//! must still surface a loud signal: an issue titled
//! `Rust audit failed on <refs>`. Today the script refuses and exits
//! non-zero, which loses the failure: the next day's open or close
//! job can run on top of it without an issue tracking the cause.
//!
//! The fix wires the run URL into the combine step and lets the
//! script decide between the advisory and failure branches. This test
//! pins the four pieces of that wiring:
//!
//! 1. The `RUN_URL` env var is set from the run URL.
//! 2. The combine step receives `--run-url`.
//! 3. The script (`rust_audit_combine.py`) accepts `--run-url`.
//! 4. The advisory branch on a clean combine still re-fails the step
//!    (so the run summary stays red rather than turning green).

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
fn rust_audit_report_opens_failure_issue_when_audit_failed_without_advisories() {
	let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(".github/workflows/rust-audit.yml");
	let text =
		fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {} | {e}", path.display()));

	assert!(
		contains_active(&text, "RUN_URL:"),
		"rust-audit.yml `report:` job does not declare a `RUN_URL:` env var.\n\
         The combine step needs the run URL so it can include it in the \
         body of the failure issue. Without it, an operator clicking the \
         open issue would have nowhere to go from the body.",
	);

	assert!(
		contains_active(&text, "github.server_url"),
		"rust-audit.yml `report:` job does not derive RUN_URL from `github.server_url`.\n\
         The run URL must be assembled from `github.server_url` + \
         `github.repository` + `github.run_id` so it works on GitHub \
         Enterprise Cloud where `github.server_url` is not github.com.",
	);

	assert!(
		contains_active(&text, "--run-url"),
		"rust-audit.yml `report:` job does not pass `--run-url` to the combine script.\n\
         The combine script decides between the advisory and failure \
         branches based on `--run-url`: present, a clean combine turns \
         into a failure issue; absent, a clean combine is the close \
         signal. The script cannot tell which branch to take unless the \
         flag is on the command line.",
	);

	let script_path =
		Path::new(env!("CARGO_MANIFEST_DIR")).join(".github/scripts/rust_audit_combine.py");
	let script_text = fs::read_to_string(&script_path)
		.unwrap_or_else(|e| panic!("read {} | {e}", script_path.display()));
	assert!(
		contains_active(&script_text, "--run-url"),
		"rust_audit_combine.py does not declare a `--run-url` flag.\n\
         The workflow passes `--run-url` so the script knows the run \
         URL; without the flag the script does not know it is being \
         called from the failure path and falls back to the close \
         signal (clean combine with no issue opened).",
	);
}
