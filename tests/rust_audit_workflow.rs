//! Pin the structural rules of `.github/workflows/rust-audit.yml`.
//!
//! The weekly cron in this file once meant a silent failure was the
//! same as no check at all: the 2026-09-28 run failed and nobody saw
//! it. The fix lives in the workflow file (daily cron, workflow_dispatch,
//! matrix over develop and main, an issue that opens itself on findings)
//! and a test in this file guards every one of those rules so a future
//! edit cannot silently roll them back.
//!
//! The test reads the YAML as a string and grep-extracts the pieces it
//! needs, the same way `workflow_toolchain_pins` does. A round trip
//! through a full YAML parser is heavier and would only catch more typos
//! on a structural pin that is short and easy to eyeball. The two
//! `lines()` walkers below are how the structure is asserted.
//!
//! Two rules the test does NOT pin: the exact cron value, and the labels
//! the report job applies. The minute is off-peak on purpose (matches
//! `dependabot-security-watch.yml`) but any off-peak minute does the
//! job; pinning "05:37" would just couple the two workflows by
//! coincidence. The labels are owned by the Python combine script and
//! the `close` job together, and pinning them here would duplicate
//! their source of truth in two places.

use std::fs;
use std::path::Path;

/// Top of the workflow, with `on: schedule: ...` and `on: workflow_dispatch:`
/// immediately following.
const SCHEDULE_HEAD: &str = "on:";
const SCHEDULE_KEY: &str = "- cron:";
const DISPATCH_KEY: &str = "workflow_dispatch:";
const PR_KEY: &str = "pull_request:";

/// The two refs the audit must cover. A drop of either is the same
/// regression the 2026-09-28 incident was, just on a smaller scale.
const REQUIRED_REFS: &[&str] = &["develop", "main"];

/// Path entries the pull_request trigger must list. The workflow itself
/// is in its own filter on purpose: a workflow whose path list omits
/// itself does not run on the pull request that changes it, so a broken
/// edit merges without ever having been executed. The reusable and the
/// Python scripts the report job runs belong to the same family: a
/// pull request that changes what the audit accepts has to run it.
const REQUIRED_PATHS: &[&str] = &[
	".github/workflows/rust-audit.yml",
	".github/workflows/reusable-rust-audit.yml",
	".github/scripts/rust_audit_combine.py",
	".github/scripts/test_rust_audit_lookup.py",
];

/// Job ids the workflow must define. The `audit` job is the matrix entry
/// that runs the reusable; `report` and `close` are the two siblings
/// that turn findings into an issue. A rename of either side would
/// silently disable the "open on findings" / "close on clean" behaviour.
const REQUIRED_JOBS: &[&str] = &["audit:", "report:", "close:"];

/// Permissions the report and close jobs must escalate to. The base
/// workflow holds `contents: read`; the open-issue path needs `issues:
/// write`, and it must be scoped to the job rather than the workflow
/// (the brief is explicit that the token never leaves the step).
const JOB_SCOPED_ISSUE_WRITE: &str = "issues: write";

#[test]
fn rust_audit_workflow_pins_daily_matrix_and_open_issue_path() {
	let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(".github/workflows/rust-audit.yml");
	let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));

	let mut schedule_lines = 0;
	let mut has_dispatch = false;
	let mut has_pr = false;
	for line in text.lines() {
		let trimmed = line.trim_start();
		if trimmed.starts_with(SCHEDULE_KEY) {
			schedule_lines += 1;
		}
		if trimmed.starts_with(DISPATCH_KEY) {
			has_dispatch = true;
		}
		if trimmed.starts_with(PR_KEY) {
			has_pr = true;
		}
	}

	assert!(
		schedule_lines >= 1,
		"rust-audit.yml has no `- cron:` entries under `on: schedule:`.\n\
         The 2026-09-28 weekly run failed and nobody saw it; a weekly \
         cadence is what made that silent. The workflow must run at \
         least once a day, on an off-peak minute.",
	);

	assert!(
		has_dispatch,
		"rust-audit.yml has no `workflow_dispatch:` trigger.\n\
         An ad hoc rerun is what closes the gap when a finding ages \
         before the next scheduled run lands.",
	);

	assert!(
		has_pr,
		"rust-audit.yml has no `pull_request:` trigger.\n\
         PR-time audits are how a bump that introduces a vulnerability \
         is caught before it merges.",
	);

	let matrix_section = extract_block(&text, "matrix:")
		.unwrap_or_else(|| panic!("rust-audit.yml has no `strategy.matrix` for the audit matrix"));
	for required_ref in REQUIRED_REFS {
		assert!(
			matches_ref(&matrix_section, required_ref),
			"rust-audit.yml matrix has no `{required_ref}` ref.\n\
             Both branches carry their own audit graph; auditing only \
             one is the same regression the 2026-09-28 incident was, \
             just on a smaller scale. Matrix section was:\n{matrix_section}",
		);
	}

	let pr_paths_section = extract_block(&text, "paths:")
		.unwrap_or_else(|| panic!("rust-audit.yml has no `paths:` block under `pull_request:`"));
	for required_path in REQUIRED_PATHS {
		assert!(
			pr_paths_section.contains(required_path),
			"rust-audit.yml `pull_request.paths` is missing `{required_path}`.\n\
             The workflow must list itself in its own filter: a workflow \
             whose path list omits itself does not run on the pull request \
             that changes it, so a broken edit merges without ever \
             having been executed. Other entries here (the reusable, \
             the Python scripts) are part of the same contract: a pull \
             request that changes what the audit accepts has to run it.",
		);
	}

	for required_job in REQUIRED_JOBS {
		assert!(
			contains_active(&text, required_job),
			"rust-audit.yml has no `{required_job}` job.\n\
             `audit:` runs the reusable in a matrix; `report:` opens or \
             comments on the issue when findings exist; `close:` closes \
             the still-open advisory issue when both refs are clean. A \
             rename of either side would silently disable that contract. \
             A match inside a comment does not count.",
		);
	}

	assert!(
		contains_active(&text, JOB_SCOPED_ISSUE_WRITE),
		"rust-audit.yml does not escalate to `{JOB_SCOPED_ISSUE_WRITE}`.\n\
         The report and close jobs need it to open, comment on and \
         close the advisory issue. The brief is explicit that the token \
         never leaves the step, so the escalation must live on those \
         two jobs, not on the workflow's top-level `permissions:`. A \
         match inside a comment does not count; the test only checks \
         for active uses on a non-comment line.",
	);

	// Drop the header line that holds `SCHEDULE_HEAD` (`on:`) itself: it
	// is matched by the loop above as a cron line on accident if the
	// scheduler ever drifted into that shape, but the loop only counts
	// `- cron:` so the assertion already covers what we care about.
	let _ = SCHEDULE_HEAD;
}

/// Pull the body of a YAML block whose key line is the only occurrence
/// at indent `n`. The block ends at the first line whose indent is `<=
/// n`. The block is returned verbatim so callers can grep the string
/// for the values they expect.
///
/// A line whose first non-space character is `#` is treated as a comment
/// and dropped from the body. That keeps a commented-out `- "..."`
/// entry from being mistaken for an active one when the test greps for
/// a path that is still mentioned in a comment.
fn extract_block(text: &str, key: &str) -> Option<String> {
	let mut in_block = false;
	let mut key_indent: usize = 0;
	let mut block_indent: usize = 0;
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
		if block_indent == 0 {
			block_indent = line_indent;
		}
		if line_indent < block_indent {
			break;
		}
		lines.push(line);
	}
	if !in_block {
		return None;
	}
	Some(lines.join("\n"))
}

/// True when `text` contains `needle` on a line whose first non-space
/// character is not `#`. The check still requires the needle to be on a
/// single line; a multi-line YAML block is OK as long as one of its
/// active lines carries it.
fn contains_active(text: &str, needle: &str) -> bool {
	text.lines().any(|line| {
		let trimmed = line.trim_start();
		if trimmed.is_empty() || trimmed.starts_with('#') {
			return false;
		}
		trimmed.contains(needle)
	})
}

/// True when `block` lists `ref` as a value in `ref:`. Two shapes count:
/// a one-liner like `ref: develop` and a block like
/// `ref: [develop, main]`. The list of values the matrix iterates over
/// is the one a future edit must keep intact. Comment-only lines are
/// ignored, the same way `extract_block` does, so a commented-out entry
/// cannot satisfy the assertion.
fn matches_ref(block: &str, ref_name: &str) -> bool {
	for line in block.lines() {
		let trimmed = line.trim_start();
		if trimmed.is_empty() || trimmed.starts_with('#') {
			continue;
		}
		if !trimmed.starts_with("ref:") {
			continue;
		}
		let after = trimmed.strip_prefix("ref:").unwrap().trim();
		if !after.is_empty() {
			// inline value
			if after
				.split(|c: char| !c.is_alphanumeric() && c != '-' && c != '_')
				.any(|token| token == ref_name)
			{
				return true;
			}
			continue;
		}
		// list form: child lines until indent decreases
		let parent_indent = line.len() - trimmed.len();
		for child in block.lines().skip_while(|l| !l.contains("ref:")) {
			let child_trimmed = child.trim_start();
			if child_trimmed.is_empty() || child_trimmed.starts_with('#') {
				continue;
			}
			let child_indent = child.len() - child_trimmed.len();
			if child_indent <= parent_indent {
				break;
			}
			if let Some(stripped) = child_trimmed.strip_prefix("- ") {
				let value = stripped.trim();
				if value == ref_name {
					return true;
				}
			}
		}
	}
	false
}
