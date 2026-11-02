//! Write a stub program a test then runs by path.
//!
//! Writing a script in this process and executing it straight away is racy
//! when other test threads fork: a child keeps the writer's descriptor open
//! until its own `exec`, and the kernel refuses to exec a file that is still
//! open for writing ("Text file busy", `ETXTBSY`). Here a child process does
//! the writing, so this process never holds a descriptor a sibling fork could
//! inherit, and the file is closed for writing when `write_executable` returns.
//! Meant for `#[path]` inclusion, so it depends on nothing else in `common`.
#![allow(dead_code)]

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};

/// Create (or replace) `path` with `body` and mark it executable.
pub fn write_executable(path: &Path, body: impl AsRef<[u8]>) {
	let mut writer = Command::new("/bin/sh")
		.args(["-c", "cat > \"$1\"", "write-executable"])
		.arg(path)
		.stdin(Stdio::piped())
		.spawn()
		.expect("spawn the stub writer");
	writer
		.stdin
		.take()
		.expect("writer stdin")
		.write_all(body.as_ref())
		.expect("send the stub body");
	let status = writer.wait().expect("wait for the stub writer");
	assert!(status.success(), "the stub writer failed: {status}");
	std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).expect("chmod 0755");
}
