//! Every audited workspace has to reach the report, under its own name.
//!
//! Three things had to be true at once and none of them was. The upload step
//! ran before the extra lockfiles were audited, so no artifact ever carried
//! the second workspace. The extra audit named its report after the file's
//! base name, so `fuzz/Cargo.lock` produced `audit-Cargo.json` while the upload
//! listed `audit-fuzz.json`. And the download merged every artifact into one
//! flat tree, where the second ref's `audit.json` landed on top of the first
//! and the combine script, which reads `audit-json-*/audit.json`, found
//! nothing.
//!
//! The first test below runs the extra-lockfile step for real, with a `cargo`
//! stub that stands in for the audit, and checks the name on disk. The
//! remaining ones pin the order of the steps, the transport and the reader,
//! so each of the three halves cannot regress on its own.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

/// The lockfile the caller passes today. The name it produces is what the rest
/// of the chain has to carry.
const FUZZ_LOCKFILE: &str = "fuzz/Cargo.lock";

fn reusable() -> String {
	read(".github/workflows/reusable-rust-audit.yml")
}

fn read(relative: &str) -> String {
	let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
	fs::read_to_string(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

/// The lines of the step named `name`, up to the next sibling step.
fn extract_step(text: &str, name: &str) -> String {
	let mut lines: Vec<&str> = Vec::new();
	let mut inside = false;
	let mut step_indent = 0;
	for line in text.lines() {
		let trimmed = line.trim_start();
		let indent = line.len() - trimmed.len();
		if !inside {
			if trimmed.starts_with("- name: ") && trimmed.contains(name) {
				inside = true;
				step_indent = indent;
			}
			continue;
		}
		// The lines are kept verbatim: the `run: |` body under them is shell,
		// and its own indentation is what tells the extractor where it ends.
		if !trimmed.is_empty() && indent < step_indent
			|| (indent == step_indent && trimmed.starts_with("- "))
		{
			break;
		}
		lines.push(line);
	}
	assert!(inside, "the workflow has no step named {name:?}");
	lines.join("\n")
}

/// The shell body of a step's `run: |` block, with the block indent removed.
fn extract_run_block(step: &str) -> String {
	let lines: Vec<&str> = step.lines().collect();
	let start = lines
		.iter()
		.position(|line| line.trim_start().starts_with("run: |"))
		.unwrap_or_else(|| panic!("the step has no `run: |` block:\n{step}"));
	let indent = lines[start].len() - lines[start].trim_start().len() + 2;
	lines[start + 1..]
		.iter()
		.take_while(|line| line.trim().is_empty() || line.len() - line.trim_start().len() >= indent)
		.map(|line| line.get(indent..).unwrap_or(""))
		.collect::<Vec<_>>()
		.join("\n")
}

/// The `path:` entries of a step, as the patterns upload-artifact receives.
fn extract_path_patterns(step: &str) -> Vec<String> {
	let mut lines: Vec<&str> = Vec::new();
	let mut inside = false;
	let mut key_indent = 0;
	for line in step.lines() {
		let trimmed = line.trim_start();
		let indent = line.len() - trimmed.len();
		if !inside {
			if trimmed.starts_with("path:") {
				inside = true;
				key_indent = indent;
			}
			continue;
		}
		if trimmed.is_empty() {
			continue;
		}
		if indent <= key_indent {
			break;
		}
		lines.push(trimmed);
	}
	lines.into_iter().map(str::to_owned).collect()
}

/// Whether `name` matches `pattern`. Only `*` is supported, which is all the
/// upload paths use.
fn glob_matches(pattern: &str, name: &str) -> bool {
	match pattern.split_once('*') {
		None => pattern == name,
		Some((prefix, suffix)) => {
			name.len() >= prefix.len() + suffix.len()
				&& name.starts_with(prefix)
				&& name.ends_with(suffix)
		}
	}
}

/// Run the extra-lockfile step against `lockfile` in a fixture tree and return
/// the report names it wrote.
fn audited_reports(lockfile: &str) -> Vec<String> {
	let dir = tempfile::tempdir().unwrap();
	let root = dir.path();
	let workspace = root.join(lockfile).parent().unwrap().to_path_buf();
	std::fs::create_dir_all(&workspace).unwrap();
	std::fs::write(root.join(lockfile), "# fixture lockfile\n").unwrap();
	let bin = root.join("bin");
	std::fs::create_dir(&bin).unwrap();
	// A cargo that reports nothing and records the lockfile it was handed.
	let cargo = bin.join("cargo");
	std::fs::write(
		&cargo,
		"#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$CARGO_LOG\"\n\
		 printf '{\"vulnerabilities\":{\"found\":false,\"count\":0,\"list\":[]}}'\nexit 0\n",
	)
	.unwrap();
	fs::set_permissions(&cargo, fs::Permissions::from_mode(0o755)).unwrap();
	let block = extract_run_block(&extract_step(&reusable(), "extra lockfiles"));
	let log = root.join("cargo.log");
	let output = Command::new("/bin/sh")
		.args(["-c", &block])
		.current_dir(root)
		.env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
		.env("CARGO_LOG", &log)
		.env("EXTRA_LOCKFILES", lockfile)
		.output()
		.unwrap();
	assert!(
		output.status.success(),
		"the extra-lockfile step must not fail on a clean workspace: {}",
		String::from_utf8_lossy(&output.stderr)
	);
	assert!(
		log_contents(&log).contains(FUZZ_LOCKFILE),
		"the step must audit the lockfile it was given; cargo was called with: {}",
		log_contents(&log)
	);
	std::fs::read_dir(root)
		.unwrap()
		.filter_map(Result::ok)
		.map(|entry| entry.file_name().to_string_lossy().into_owned())
		.filter(|name| name.ends_with(".json"))
		.collect()
}

fn log_contents(path: &Path) -> String {
	fs::read_to_string(path).unwrap_or_default()
}

#[test]
fn the_extra_workspace_report_is_named_after_its_workspace() {
	let reports = audited_reports(FUZZ_LOCKFILE);
	assert_eq!(
		reports,
		vec!["audit-fuzz-Cargo.json".to_owned()],
		"auditing fuzz/Cargo.lock must produce one report named after that workspace. A name taken \
		 from the file alone is `audit-Cargo.json`, which no upload path listed and no reader \
		 recognised."
	);
}

#[test]
fn the_upload_step_runs_after_the_extra_audit_and_carries_its_reports() {
	let workflow = reusable();
	let upload = extract_step(&workflow, "Upload cargo audit JSON");
	let extra_line = workflow
		.lines()
		.position(|line| line.contains("- name: Run cargo audit on the extra lockfiles"))
		.expect("the reusable audits the extra lockfiles");
	let upload_line = workflow
		.lines()
		.position(|line| line.contains("- name: Upload cargo audit JSON"))
		.expect("the reusable uploads the audit JSON");
	assert!(
		extra_line < upload_line,
		"the extra lockfiles are audited at line {} and the upload runs at line {}. An upload \
		 placed first ships an artifact with the root audit only, and the second workspace is \
		 invisible to the open-issue decision.",
		extra_line + 1,
		upload_line + 1
	);
	assert!(
		upload.contains("always()"),
		"the upload must run when the audit failed, or a vulnerable ref ships no report at all. \
		 The step was:\n{upload}"
	);
	assert!(
		!upload.contains("hashFiles('audit.json')"),
		"the upload guard must cover every report, not only the root one: with only \
		 `hashFiles('audit.json')` a root audit that crashed before writing JSON drops the extra \
		 workspace's report on the floor. The step was:\n{upload}"
	);
	let patterns = extract_path_patterns(&upload);
	assert!(
		!patterns.is_empty(),
		"the upload step declares no path:\n{upload}"
	);
	for report in audited_reports(FUZZ_LOCKFILE) {
		assert!(
			patterns
				.iter()
				.any(|pattern| glob_matches(pattern, &report)),
			"the upload path {:?} does not match {report}, so that report would never reach the \
			 report job.\nUpload step was:\n{upload}",
			patterns
		);
	}
}

#[test]
fn the_download_keeps_one_directory_per_ref() {
	let report = read(".github/workflows/rust-audit.yml");
	let download = extract_step(&report, "Download every cargo audit JSON");
	assert!(
		download.contains("audit-json-*"),
		"the download must keep matching every ref's artifact:\n{download}"
	);
	let active: Vec<&str> = download
		.lines()
		.map(str::trim_start)
		.filter(|line| !line.is_empty() && !line.starts_with('#'))
		.collect();
	assert!(
		!active.iter().any(|line| line.starts_with("merge-multiple")),
		"merging the artifacts flattens them into one directory where the second ref's \
		 `audit.json` overwrites the first. Each artifact has to land in its own subdirectory, \
		 which is what the combine script reads.\nDownload step was:\n{download}"
	);
	let combine = read(".github/scripts/rust_audit_combine.py");
	assert!(
		combine.contains("audit-json-*"),
		"the combine script must read the layout the download produces, one directory per ref."
	);
}
