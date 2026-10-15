//! Spawn the real `epistle` against a throwaway configuration and read
//! its stdout as one JSON document.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};

/// A password the policy accepts, piped to `account add`. Integration
/// tests cannot reach the crate's private test fixtures, so it is
/// spelled here; it protects nothing outside the temporary directory.
pub const PASSWORD: &[u8] = b"Zq8!vT3#mL0@pW6$\n";

/// A temporary data directory and the configuration pointing at it.
pub struct Env {
	pub dir: tempfile::TempDir,
	pub config: String,
}

impl Env {
	/// The data directory the configuration names.
	#[allow(dead_code)]
	pub fn data_dir(&self) -> std::path::PathBuf {
		self.dir.path().join("data")
	}
}

/// A configuration for `mail.example.org` serving `example.org`, with
/// `extra` appended verbatim.
pub fn env(extra: &str) -> Env {
	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path().join("mail.toml");
	std::fs::create_dir(dir.path().join("data")).expect("data dir");
	std::fs::write(
		&path,
		format!(
			"hostname = \"mail.example.org\"\ndata_dir = {:?}\ndomains = [\"example.org\"]\n{extra}",
			dir.path().join("data")
		),
	)
	.expect("write config");
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
	let config = path.to_string_lossy().into_owned();
	Env { dir, config }
}

/// Run `epistle` with `args`, `stdin` piped in, colour off.
pub fn epistle(args: &[&str], stdin: &[u8]) -> Output {
	epistle_in(args, stdin, None)
}

/// [`epistle`] with `path_first` put in front of `PATH`, for a stub
/// `podup`.
pub fn epistle_in(args: &[&str], stdin: &[u8], path_first: Option<&Path>) -> Output {
	let mut command = Command::new(env!("CARGO_BIN_EXE_epistle"));
	command
		.args(args)
		.env("NO_COLOR", "1")
		.stdin(Stdio::piped())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped());
	if let Some(dir) = path_first {
		let mut path = dir.as_os_str().to_owned();
		path.push(":");
		path.push(std::env::var_os("PATH").unwrap_or_default());
		command.env("PATH", path);
	}
	let mut child = command.spawn().expect("spawn epistle");
	child
		.stdin
		.take()
		.expect("stdin")
		.write_all(stdin)
		.expect("write stdin");
	child.wait_with_output().expect("wait epistle")
}

/// The exit code and stdout of a run, with stdout parsed as exactly one
/// line of JSON. stderr is returned too: it may carry notes, never JSON.
pub fn json(output: &Output) -> (i32, serde_json::Value) {
	let stdout = String::from_utf8_lossy(&output.stdout);
	let stderr = String::from_utf8_lossy(&output.stderr);
	assert_eq!(
		stdout.lines().count(),
		1,
		"stdout is not one line of JSON (exit {:?}); stderr: {stderr}",
		output.status.code()
	);
	let value = serde_json::from_str(&stdout).unwrap_or_else(|error| {
		panic!("stdout is not JSON: {error}; stderr: {stderr}");
	});
	(output.status.code().unwrap_or(-1), value)
}

/// Create the dynamic account `name` with one address at example.org.
pub fn add_account(env: &Env, name: &str) {
	let address = format!("{name}@example.org");
	let output = epistle(
		&[
			"account",
			"--config",
			&env.config,
			"add",
			name,
			"--address",
			&address,
		],
		PASSWORD,
	);
	assert!(
		output.status.success(),
		"account add failed: {}",
		String::from_utf8_lossy(&output.stderr)
	);
}
