//! Pin that the issue body is passed to `gh` via `--body-file`, and
//! that no `${{ }}` interpolation of untrusted data appears inside any
//! `run:` block in the rust-audit workflow tree.
//!
//! The body of the issue is built from cargo audit advisory titles and
//! URLs, which are public but still come from the dependency graph.
//! `${{ ... }}` interpolation in a `run:` block would let an attacker
//! who controls an advisory's title break out of the quoted shell
//! argument and run arbitrary commands with the job's `GITHUB_TOKEN`.
//! `--body-file` reads the body from a file the previous step wrote;
//! the body text is never part of the command line.

use std::fs;
use std::path::Path;

/// Walk every `run:` block in the workflow and return the bodies as a
/// single string. `run:` may be `run: |` (literal) or `run: >` (folded);
/// either way the block ends at the first shallower-indent line or at
/// the next sibling step / job key.
fn collect_run_blocks(text: &str) -> Vec<String> {
	let mut blocks = Vec::new();
	let mut in_run = false;
	let mut run_indent: usize = 0;
	let mut lines: Vec<&str> = Vec::new();
	for line in text.lines() {
		let trimmed = line.trim_start();
		if !in_run {
			if trimmed.starts_with("run: |") || trimmed.starts_with("run: >") {
				in_run = true;
				run_indent = line.len() - trimmed.len();
				lines.clear();
				lines.push(line);
			}
			continue;
		}
		if trimmed.is_empty() {
			lines.push(line);
			continue;
		}
		let line_indent = line.len() - trimmed.len();
		if line_indent <= run_indent {
			blocks.push(lines.join("\n"));
			in_run = false;
			if trimmed.starts_with("run: |") || trimmed.starts_with("run: >") {
				in_run = true;
				run_indent = line_indent;
				lines.clear();
				lines.push(line);
			} else {
				lines.clear();
			}
			continue;
		}
		lines.push(line);
	}
	if in_run {
		blocks.push(lines.join("\n"));
	}
	blocks
}

#[test]
fn rust_audit_passes_body_via_body_file_not_command_line() {
	let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(".github/workflows/rust-audit.yml");
	let text =
		fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {} | {e}", path.display()));

	// The advisory issue is opened or commented on in the `report:`
	// job's run block. Its body must reach `gh` via `--body-file`, never
	// via `--body "$body"` (which puts untrusted advisory text onto the
	// command line where it can be subverted by quoting tricks).
	let report_runs: Vec<String> = collect_run_blocks(&text)
		.into_iter()
		.filter(|b| b.contains("gh issue create") || b.contains("gh issue comment"))
		.collect();
	assert!(
		!report_runs.is_empty(),
		"rust-audit.yml has no `run:` block that calls `gh issue create` \
         or `gh issue comment`. The report job is what writes to issues; \
         if it is gone the open/comment contract has been deleted.",
	);
	for run in &report_runs {
		assert!(
			run.contains("--body-file"),
			"rust-audit.yml report-job run block calls `gh issue create`/`comment` \
             without `--body-file`. The body must reach `gh` from a file the \
             previous step wrote, never from the command line where it can be \
             subverted by an attacker who controls an advisory's title.\n\
             Block was:\n{run}",
		);
		assert!(
			!run.contains("--body \"$body\""),
			"rust-audit.yml report-job run block calls `gh issue create`/`comment` \
             with `--body \"$body\"`. The body is advisory text and must reach \
             `gh` from a file (--body-file), not from the command line.\n\
             Block was:\n{run}",
		);
	}

	// No `${{ ... }}` interpolation of any data appears inside any
	// `run:` block across the two workflow files. `${{ ... }}` is
	// substituted by GitHub Actions before bash sees the line, so a
	// hostile advisory id with a closing quote could break out of the
	// surrounding string. The fix is to read every variable through
	// `env:` and reference it as a bash variable inside the script.
	for path_str in &[
		".github/workflows/rust-audit.yml",
		".github/workflows/reusable-rust-audit.yml",
	] {
		let p = Path::new(env!("CARGO_MANIFEST_DIR")).join(path_str);
		let t = fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {} | {e}", p.display()));
		for run in collect_run_blocks(&t) {
			assert!(
				!run.contains("${{"),
				"{path_str} has a `run:` block that interpolates a `${{ ... }}` expression.\n\
                 GitHub Actions expands `${{ ... }}` before bash parses the line, \
                 so a hostile value (an advisory title, a ref name, anything \
                 attacker-controlled) can break out of the surrounding quote and \
                 run arbitrary commands with the job's GITHUB_TOKEN. Move the \
                 value into `env:` and reference it as a bash variable inside \
                 the script. Block was:\n{run}",
			);
		}
	}
}
