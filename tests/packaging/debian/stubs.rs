use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

pub(super) fn write_stub(path: &Path, body: &str) {
	let staging = tempfile::tempdir_in(path.parent().unwrap()).unwrap();
	let temporary = staging.path().join("stub");
	// Writing in a child keeps concurrent test forks from inheriting the writer.
	// Renaming alone cannot close a descriptor inherited before publication.
	let status = Command::new("/bin/sh")
		.args([
			"-c",
			"printf '#!/bin/sh\\n%s\\n' \"$1\" > \"$2\"",
			"write-stub",
		])
		.arg(body)
		.arg(&temporary)
		.status()
		.unwrap();
	assert_eq!(status.code(), Some(0), "stub writer must exit successfully");
	fs::rename(&temporary, path).unwrap();
	fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

#[cfg(test)]
#[path = "stubs_tests_exec.rs"]
mod tests_exec;
