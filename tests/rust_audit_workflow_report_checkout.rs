//! The audit report job has to have the combine script before it runs it.
//!
//! `report` downloads the audit JSON artifacts and then runs
//! `.github/scripts/rust_audit_combine.py`. Every job in a workflow gets its
//! own workspace, and the checkout the reusable performs happens in the
//! `audit` job, not here, so the script was simply not on disk: the daily run
//! failed at the step that was supposed to open the issue, before `gh` was
//! ever called, and the reason it failed was a missing file rather than the
//! advisory that triggered the run.
//!
//! The checkout is the workflow's own code on the ref that triggered the run,
//! and it runs with `persist-credentials: false`, so the token that opens the
//! issue never lands in `.git/config`. The job asks for `contents: read` on
//! top of the `issues: write` it already had.

use std::fs;
use std::path::Path;

/// The job whose key line is `key:` at two spaces of indent.
fn extract_job_block(text: &str, key: &str) -> Option<String> {
	let mut in_block = false;
	let mut key_indent = 0;
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
		if line.len() - trimmed.len() <= key_indent {
			break;
		}
		lines.push(line);
	}
	in_block.then(|| lines.join("\n"))
}

/// The lines indented under the first `key:` line of `text`.
fn extract_nested_block(text: &str, key: &str) -> Option<String> {
	let mut lines: Vec<&str> = Vec::new();
	let mut key_indent = 0;
	let mut inside = false;
	for line in text.lines() {
		let trimmed = line.trim_start();
		if !inside {
			if trimmed.starts_with(key) {
				inside = true;
				key_indent = line.len() - trimmed.len();
			}
			continue;
		}
		if trimmed.is_empty() || trimmed.starts_with('#') {
			continue;
		}
		if line.len() - trimmed.len() <= key_indent {
			break;
		}
		lines.push(trimmed);
	}
	inside.then(|| lines.join("\n"))
}

/// The lines of the step that opens with `needle`, up to the next sibling
/// step or the first line indented less.
fn extract_step(text: &str, needle: &str) -> String {
	let mut lines: Vec<&str> = Vec::new();
	let mut inside = false;
	let mut step_indent = 0;
	for line in text.lines() {
		let trimmed = line.trim_start();
		let indent = line.len() - trimmed.len();
		if !inside {
			if trimmed.starts_with("- ") && line.contains(needle) {
				inside = true;
				step_indent = indent;
				lines.push(trimmed);
			}
			continue;
		}
		if trimmed.is_empty() || trimmed.starts_with('#') {
			continue;
		}
		if indent <= step_indent && trimmed.starts_with("- ") || indent < step_indent {
			break;
		}
		lines.push(trimmed);
	}
	assert!(inside, "the workflow has no step matching {needle:?}");
	lines.join("\n")
}

fn workflow(name: &str) -> String {
	let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(".github/workflows/{name}"));
	fs::read_to_string(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

/// The first active line of `block` containing `needle`.
fn first_line_with<'a>(block: &'a str, needle: &str) -> Option<(usize, &'a str)> {
	block
		.lines()
		.filter(|line| {
			let trimmed = line.trim_start();
			!trimmed.is_empty() && !trimmed.starts_with('#')
		})
		.enumerate()
		.find(|(_, line)| line.contains(needle))
}

#[test]
fn the_report_job_checks_out_the_tree_before_it_runs_the_combine_script() {
	let report = extract_job_block(&workflow("rust-audit.yml"), "report:")
		.expect("rust-audit.yml has a `report:` job");

	let checkout = first_line_with(&report, "actions/checkout@");
	let run = first_line_with(&report, "run:");
	assert!(
		checkout.is_some()
			&& run.is_some()
			&& checkout.expect("no checkout").0 < run.expect("no run").0,
		"the checkout ({checkout:?}) must come before the step that runs the combine script \
		 ({run:?}). Each job has its own workspace, so without a checkout in this job the script \
		 is not on disk and the daily run dies before it can open the advisory issue it exists \
		 to open.\nJob block was:\n{report}",
	);
	let step = extract_step(&report, "actions/checkout@");
	assert!(
		step.contains("persist-credentials: false"),
		"the checkout must not leave the issue-opening token in .git/config, where a later step \
		 could read it. The step was:\n{step}",
	);
	let pin = step
		.split("actions/checkout@")
		.nth(1)
		.unwrap()
		.split_whitespace()
		.next()
		.unwrap_or_default();
	assert_eq!(
		pin.len(),
		40,
		"actions/checkout must be pinned by its full commit SHA, like every other action in the \
		 tree; the step reads:\n{step}"
	);
	assert!(
		pin.chars().all(|c| c.is_ascii_hexdigit()),
		"the checkout pin must be hexadecimal: {pin:?}"
	);
}

#[test]
fn the_report_job_is_allowed_to_read_what_it_checks_out() {
	let report = extract_job_block(&workflow("rust-audit.yml"), "report:")
		.expect("rust-audit.yml has a `report:` job");
	let permissions = extract_nested_block(&report, "permissions:")
		.expect("rust-audit.yml `report:` job declares no permissions");

	for needed in ["contents: read", "issues: write"] {
		assert!(
			permissions.lines().any(|line| line == needed),
			"the report job needs {needed:?}: reading the repository is what the checkout above \
			 takes, and writing issues is what the step that opens or comments on the advisory \
			 takes. The permissions block was:\n{permissions}"
		);
	}
	for forbidden in ["contents: write", "pull-requests: write", "actions: write"] {
		assert!(
			!permissions.lines().any(|line| line == forbidden),
			"the report job has no reason to hold {forbidden:?}. The permissions block was:\n\
			 {permissions}",
		);
	}
}
