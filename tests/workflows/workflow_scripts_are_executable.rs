//! A script a workflow runs directly must be stored in git with mode 100755.
//!
//! `run: .github/scripts/sign_release.sh ...` asks the runner to execute the
//! file itself, so the executable bit has to live in the index. A script
//! committed as 100644 works on a developer's disk, where `chmod` was run once,
//! and fails on the runner with `Permission denied`. That broke two release
//! rehearsals. Scripts started through an interpreter (`bash x.sh`,
//! `python3 x.py`) do not need the bit and are left alone.
//!
//! The test reads every workflow, takes the first word of each command, and
//! keeps the ones that name a tracked file. It then asks `git ls-files -s` for
//! the mode of each.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::process::Command;

/// Fewer direct invocations than this means the extraction stopped seeing the
/// workflows, and an empty pass proves nothing.
const MIN_DIRECT_SCRIPTS: usize = 2;

fn root() -> &'static Path {
	Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn git(args: &[&str]) -> String {
	let output = Command::new("git")
		.args(args)
		.current_dir(root())
		.output()
		.expect("run git");
	assert!(output.status.success(), "git {args:?} failed");
	String::from_utf8(output.stdout).expect("git output is utf-8")
}

/// Index entries as `(mode, path)`.
fn index() -> Vec<(String, String)> {
	git(&["ls-files", "-s", "-z"])
		.split('\0')
		.filter_map(|entry| {
			let (meta, path) = entry.split_once('\t')?;
			let mode = meta.split_whitespace().next()?;
			Some((mode.to_owned(), path.to_owned()))
		})
		.collect()
}

/// The shell lines of a workflow: the value of a `run:` key, and for a block
/// scalar every following line indented deeper than the key. Path filters and
/// other YAML lists that merely name a file are not commands.
fn run_lines(text: &str) -> Vec<String> {
	let mut out = Vec::new();
	let mut block_indent: Option<usize> = None;
	for line in text.lines() {
		let indent = line.len() - line.trim_start().len();
		if let Some(key_indent) = block_indent {
			if line.trim().is_empty() || indent > key_indent {
				out.push(line.to_owned());
				continue;
			}
			block_indent = None;
		}
		let body = line.trim_start().trim_start_matches("- ");
		if let Some(value) = body.strip_prefix("run:") {
			let value = value.trim();
			if value.starts_with(['|', '>']) {
				block_indent = Some(indent + (line.trim_start().len() - body.len()));
			} else {
				out.push(value.to_owned());
			}
		}
	}
	out
}

/// Lines with a trailing backslash joined to the next one, so an argument on a
/// continuation line is not mistaken for a command.
fn joined(text: &str) -> Vec<String> {
	let mut out = Vec::new();
	let mut pending = String::new();
	for line in run_lines(text) {
		let line = line.as_str();
		match line.trim_end().strip_suffix('\\') {
			Some(head) => {
				pending.push_str(head);
				pending.push(' ');
			}
			None => {
				pending.push_str(line);
				out.push(std::mem::take(&mut pending));
			}
		}
	}
	out
}

/// The first word of every command on every non-comment line, cleaned of
/// quotes, `run:`/list markers, leading assignments and a `./` or workspace
/// prefix.
fn command_words(text: &str) -> BTreeSet<String> {
	let mut words = BTreeSet::new();
	for line in joined(text) {
		if line.trim_start().starts_with('#') {
			continue;
		}
		let line = line
			.replace("&&", ";")
			.replace("||", ";")
			.replace(['|', '(', '`'], ";");
		for segment in line.split(';') {
			let mut rest = segment.trim();
			loop {
				let before = rest;
				for prefix in ["- ", "run:", "|", ">"] {
					rest = rest.strip_prefix(prefix).unwrap_or(rest).trim_start();
				}
				rest = rest.strip_prefix('$').unwrap_or(rest);
				if rest == before {
					break;
				}
			}
			let mut tokens = rest.split_whitespace();
			let mut first = tokens.next().unwrap_or("");
			while first.contains('=') && !first.contains('/') {
				first = tokens.next().unwrap_or("");
			}
			let word = first
				.trim_matches(|c| c == '"' || c == '\'')
				.trim_start_matches("${GITHUB_WORKSPACE}/")
				.trim_start_matches("$GITHUB_WORKSPACE/")
				.trim_start_matches("./");
			if !word.is_empty() {
				words.insert(word.to_owned());
			}
		}
	}
	words
}

/// Tracked files named as a command, matched exactly or as the tail of a path
/// whose checkout lives in a subfolder (`rehearsal-tools/.github/...`).
fn direct_invocations(text: &str, tracked: &[(String, String)]) -> BTreeSet<String> {
	let words = command_words(text);
	tracked
		.iter()
		.filter(|(_, path)| {
			words
				.iter()
				.any(|word| word == path || word.ends_with(&format!("/{path}")))
		})
		.map(|(_, path)| path.clone())
		.collect()
}

fn workflow_texts() -> Vec<(String, String)> {
	let dir = root().join(".github/workflows");
	let mut out = Vec::new();
	for entry in fs::read_dir(&dir).expect("read .github/workflows") {
		let path = entry.expect("dir entry").path();
		if path
			.extension()
			.is_some_and(|ext| ext == "yml" || ext == "yaml")
		{
			let text = fs::read_to_string(&path).expect("read workflow");
			let name = path.file_name().unwrap().to_string_lossy().into_owned();
			out.push((name, text));
		}
	}
	out
}

#[test]
fn scripts_a_workflow_runs_directly_are_mode_100755() {
	// A source package (dpkg-buildpackage) unpacks without `.git` and without
	// `.github`, so there is no index to read and no workflow to check. In a
	// checkout of the repository both exist and the test runs in full.
	if !root().join(".git").exists() || !root().join(".github/workflows").is_dir() {
		eprintln!(
			"SKIPPED: no .git or no .github/workflows next to Cargo.toml; \
			 script modes can only be checked in a git checkout"
		);
		return;
	}
	let tracked = index();
	let mut seen = BTreeSet::new();
	let mut wrong = Vec::new();
	for (name, text) in workflow_texts() {
		for path in direct_invocations(&text, &tracked) {
			let mode = tracked.iter().find(|(_, p)| *p == path).map(|(m, _)| m);
			if mode.map(String::as_str) != Some("100755") {
				wrong.push(format!("{name}: {path} is {mode:?}"));
			}
			seen.insert(path);
		}
	}
	assert!(
		seen.len() >= MIN_DIRECT_SCRIPTS,
		"found only {seen:?}; the extraction no longer sees the workflows"
	);
	assert!(
		wrong.is_empty(),
		"scripts run directly by a workflow must be 100755 in git \
		 (git update-index --chmod=+x <path>): {wrong:#?}"
	);
}

#[test]
fn extraction_separates_direct_runs_from_interpreter_runs() {
	let tracked: Vec<(String, String)> = ["a.sh", "b.sh", "c.py", "d.sh", "e.sh"]
		.iter()
		.map(|p| ("100644".to_owned(), format!(".github/scripts/{p}")))
		.collect();
	let text = "\
        run: .github/scripts/a.sh one \"$TAG\"
        run: bash .github/scripts/b.sh
        run: |
          set -e
          python3 .github/scripts/c.py
          VAR=1 ./.github/scripts/d.sh x
          # .github/scripts/e.sh is only mentioned here
        run: rehearsal/.github/scripts/e.sh
";
	let found: Vec<_> = direct_invocations(text, &tracked).into_iter().collect();
	assert_eq!(
		found,
		[
			".github/scripts/a.sh",
			".github/scripts/d.sh",
			".github/scripts/e.sh"
		]
	);
}
