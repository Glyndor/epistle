//! A path that is not an ordinary small file must not hang or fill memory.

use std::os::unix::fs::PermissionsExt;

use epistle::config::ConfigError;

use super::harness::{MAX_MESSAGE, VALID, file, load};

#[test]
fn a_fifo_is_refused_without_waiting_for_a_writer() {
	let dir = tempfile::tempdir().expect("dir");
	let fifo = dir.path().join("epistle.toml");
	assert!(
		std::process::Command::new("mkfifo")
			.arg("-m")
			.arg("600")
			.arg(&fifo)
			.status()
			.expect("mkfifo")
			.success()
	);
	let error = load(&fifo).expect_err("a fifo is not a configuration");
	assert!(matches!(error, ConfigError::Read { .. }), "{error:?}");
	assert!(error.to_string().contains("regular file"), "{error}");
}

#[test]
fn a_directory_is_refused_as_a_configuration() {
	let dir = tempfile::tempdir().expect("dir");
	std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).expect("mode");
	let error = load(dir.path()).expect_err("a directory is not a file");
	assert!(matches!(error, ConfigError::Read { .. }), "{error:?}");
}

#[test]
fn a_file_over_the_size_cap_is_refused_before_it_is_parsed() {
	let mut text = VALID.to_string();
	text.push_str(&"# padding\n".repeat(2_000_000));
	let file = file(text.as_bytes());
	let error = load(file.path()).expect_err("too large");
	assert!(matches!(error, ConfigError::Read { .. }), "{error:?}");
	let message = error.to_string();
	assert!(message.contains("larger than"), "{message}");
	assert!(message.len() <= MAX_MESSAGE, "{} bytes", message.len());
}

#[test]
fn a_file_just_under_the_cap_still_loads() {
	let mut text = VALID.to_string();
	text.push_str(&"# padding\n".repeat(100_000));
	let file = file(text.as_bytes());
	assert!(load(file.path()).is_ok());
}
