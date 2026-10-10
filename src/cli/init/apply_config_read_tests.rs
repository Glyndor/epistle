use super::*;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{PermissionsExt, symlink};

#[test]
fn config_read_uses_the_verified_descriptor_after_a_path_swap() {
	let dir = tempfile::tempdir_in(".").expect("tempdir");
	let path = dir.path().join("mail.toml");
	let target = dir.path().join("private.toml");
	let original = "hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n";
	fs::write(&path, original).expect("write config");
	fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("config mode");
	fs::write(&target, "[dns]\ntoken = \"opaque\" trailing-garbage\n").expect("write target");
	fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).expect("target mode");
	let opened = read_config_with(&path, |file| {
		// SAFETY: F_GETFL only inspects the flags of a live file descriptor.
		let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
		assert!(
			flags >= 0 && flags & libc::O_NONBLOCK != 0,
			"config descriptor must be nonblocking before its type is inspected"
		);
		fs::remove_file(&path).expect("unlink checked config");
		symlink(target.canonicalize().expect("absolute target"), &path).expect("swap symlink");
	})
	.expect("read checked descriptor")
	.expect("existing config");
	assert!(
		opened.text == original,
		"config read must return the bytes from the verified descriptor after a path swap"
	);
	assert_eq!(
		opened.metadata.permissions().mode() & 0o777,
		0o600,
		"config validation must use the verified descriptor permissions"
	);
	assert!(
		opened
			.validate(&path)
			.is_ok_and(|config| config.hostname == "mail.example.org"),
		"config validation must use the verified bytes and owner-only permissions after a path swap"
	);
	assert!(
		matches!(
			super::super::merge_with_read_config(&path, original, false, Some(&opened)),
			Ok(super::super::ConfigWrite::Identical)
		),
		"identical config merge must validate the snapshot without reopening the swapped path"
	);
}

#[test]
fn config_fifo_is_rejected_without_waiting_for_a_writer() {
	let dir = tempfile::tempdir_in(".").expect("tempdir");
	let path = dir.path().join("mail.toml");
	assert!(
		std::process::Command::new("mkfifo")
			.arg(&path)
			.status()
			.expect("mkfifo")
			.success(),
		"FIFO fixture must be created"
	);
	assert!(
		matches!(read_config(&path), Err(ApplyError::ConfigNotAFile(ref rejected)) if rejected == &path),
		"config FIFO must be rejected as a non-regular file without reading it"
	);
}
