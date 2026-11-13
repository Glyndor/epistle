//! The `--answers` file is read as a regular file, never through a link, and
//! a credential in it is not left readable by other users.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use super::super::read::read_file;
use crate::cli::init::apply::ApplyError;

const WITH_TOKEN: &str = "[dns]\nprovider = \"cloudflare\"\ntoken = \"SECRET-TOKEN\"\n";

fn file_with(dir: &Path, body: &str, mode: u32) -> std::path::PathBuf {
	let path = dir.join("answers.toml");
	std::fs::write(&path, body).unwrap();
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
	path
}

#[test]
fn an_inline_token_in_a_file_others_can_read_is_refused_without_the_value() {
	let dir = tempfile::tempdir().unwrap();
	for mode in [0o644, 0o640, 0o604] {
		let path = file_with(dir.path(), WITH_TOKEN, mode);
		let error = read_file(&path).unwrap_err();
		assert!(matches!(error, ApplyError::AnswersFile(..)), "{error:?}");
		let text = error.to_string();
		assert!(text.contains("group/world-accessible"), "{mode:#o}: {text}");
		assert!(!text.contains("SECRET-TOKEN"), "{text}");
	}
}

#[test]
fn an_owner_only_file_with_a_token_and_a_loose_file_without_one_are_read() {
	let dir = tempfile::tempdir().unwrap();
	let private = file_with(dir.path(), WITH_TOKEN, 0o600);
	assert_eq!(read_file(&private).unwrap(), WITH_TOKEN);
	let plain = "hostname = \"mail.example.org\"\n[dns]\ntoken_file = \"/run/secrets/dns\"\n";
	let loose = file_with(dir.path(), plain, 0o644);
	assert_eq!(read_file(&loose).unwrap(), plain);
}

#[test]
fn a_symlink_is_refused() {
	let dir = tempfile::tempdir().unwrap();
	let real = file_with(dir.path(), "hostname = \"h\"\n", 0o600);
	let link = dir.path().join("link.toml");
	std::os::unix::fs::symlink(&real, &link).unwrap();
	let error = read_file(&link).unwrap_err();
	assert!(matches!(error, ApplyError::AnswersFile(..)), "{error:?}");
	assert!(error.to_string().contains("symlink"), "{error}");
}

#[test]
fn a_directory_and_a_fifo_are_refused_not_waited_on() {
	let dir = tempfile::tempdir().unwrap();
	let error = read_file(dir.path()).unwrap_err();
	assert!(error.to_string().contains("regular file"), "{error}");
	let fifo = dir.path().join("fifo");
	let c_path = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
	// SAFETY: the path is a valid NUL-terminated string.
	assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
	let error = read_file(&fifo).unwrap_err();
	assert!(error.to_string().contains("regular file"), "{error}");
}
