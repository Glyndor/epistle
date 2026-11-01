//! The reverse-DNS block through the real binary: `init --answers` with a
//! hostname that cannot resolve, so its PTR can never be forward-confirmed.
//! Whether the sandbox has a resolver or not, the block lands on stderr,
//! names the address, does not report a match, and leaves the exit code
//! at 0.

use std::path::Path;
use std::process::{Command, Output, Stdio};

const HOST: &str = "mail.example.invalid";

fn answers(dir: &Path) -> std::path::PathBuf {
	let path = dir.join("answers.toml");
	let body = format!(
		"mode = \"manual\"\n\
		 hostname = \"{HOST}\"\n\
		 domains = [\"example.invalid\"]\n\
		 public_ipv4 = \"8.8.8.8\"\n\
		 data_dir = \"{}\"\n\
		 config_path = \"{}\"\n\
		 image = \"localhost/epistle:dev\"\n\n\
		 [services]\n\
		 database = false\n",
		dir.join("data").display(),
		dir.join("etc").join("mail.toml").display(),
	);
	std::fs::write(&path, body).expect("write answers");
	path
}

fn init(extra: &[&str]) -> (tempfile::TempDir, Output) {
	let dir = tempfile::tempdir().expect("tempdir");
	let path = answers(dir.path());
	let output = Command::new(env!("CARGO_BIN_EXE_epistle"))
		.args(["init", "--answers", path.to_str().expect("utf-8 path")])
		.args(extra)
		.stdin(Stdio::null())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.output()
		.expect("spawn epistle");
	(dir, output)
}

/// The block and its one line for 8.8.8.8: a PTR elsewhere when the
/// resolver answers, a failed lookup when there is none. Never a match.
fn assert_block(output: &Output) {
	let stderr = String::from_utf8_lossy(&output.stderr);
	assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
	assert!(output.stdout.is_empty(), "nothing goes to stdout");
	let block = stderr
		.split_once(&format!("reverse DNS (PTR), expected to name {HOST}:\n"))
		.map(|(_, block)| block)
		.unwrap_or_else(|| panic!("no PTR block on stderr: {stderr}"));
	let line = block.lines().next().unwrap_or_default();
	assert!(
		line.starts_with("  8.8.8.8: points at ") || line.starts_with("  8.8.8.8: lookup failed"),
		"the PTR of 8.8.8.8 cannot name a host that does not resolve: {line}"
	);
}

#[cfg(unix)]
#[test]
fn init_with_an_unresolvable_hostname_reports_the_ptr_and_exits_0() {
	let (dir, output) = init(&[]);
	assert_block(&output);
	assert!(
		dir.path().join("etc").join("mail.toml").exists(),
		"the run must have written the config"
	);
}

#[test]
fn dry_run_reports_the_ptr_on_stderr_and_exits_0() {
	let (dir, output) = init(&["--dry-run"]);
	assert_block(&output);
	assert!(
		!dir.path().join("data").exists(),
		"dry-run must not create data_dir"
	);
}
