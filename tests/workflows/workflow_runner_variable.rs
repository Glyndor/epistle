//! Every fixed Linux `runs-on` in `.github/workflows/*.yml` must read the
//! `CI_RUNNER` repository variable, so one setting moves the repository to a
//! self-hosted runner and deleting it moves the repository back.
//!
//! The accepted form is exactly
//! `${{ fromJSON(vars.CI_RUNNER || '"ubuntu-latest"') }}`. A literal
//! `ubuntu-latest` or `ubuntu-24.04` silently opts one job out of the switch.
//!
//! Not checked, on purpose: `runs-on: ${{ matrix.* }}`. `e2e.yml` and
//! `reusable-rust-ci.yml` (`extra-test-os`) name the OS they test on, and
//! `release.yml` builds the arm64 image and package on `ubuntu-24.04-arm`;
//! those stay GitHub-hosted.

use std::fs;
use std::path::Path;

const EXPRESSION: &str = "${{ fromJSON(vars.CI_RUNNER || '\"ubuntu-latest\"') }}";

/// `runs-on` values that may stay literal. Empty today: add `(file, value)`
/// with the reason when a Linux job must not move.
const FIXED: &[(&str, &str)] = &[];

#[test]
fn linux_jobs_read_the_runner_variable() {
	let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join(".github/workflows");
	let mut offenders = Vec::new();
	let mut with_variable = 0usize;
	for entry in fs::read_dir(&dir).expect("read .github/workflows") {
		let path = entry.expect("dir entry").path();
		if path.extension().is_none_or(|x| x != "yml") {
			continue;
		}
		let name = path.file_name().unwrap().to_string_lossy().into_owned();
		let text = fs::read_to_string(&path).expect("read workflow");
		for (n, line) in text.lines().enumerate() {
			let Some(value) = line.trim_start().strip_prefix("runs-on:") else {
				continue;
			};
			let value = value.trim();
			if value == EXPRESSION {
				with_variable += 1;
			} else if value.starts_with("ubuntu-") && !FIXED.contains(&(name.as_str(), value)) {
				offenders.push(format!("{name}:{}: runs-on: {value}", n + 1));
			}
		}
	}
	assert!(
		offenders.is_empty(),
		"Linux jobs that ignore CI_RUNNER (use {EXPRESSION}):\n{}",
		offenders.join("\n")
	);
	assert!(
		with_variable >= 30,
		"expected at least 30 jobs on the CI_RUNNER expression, found {with_variable}"
	);
}
