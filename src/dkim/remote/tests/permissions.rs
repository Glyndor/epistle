//! The socket and its directory: only the signer's own uid gets in, and
//! nothing that is not a socket is ever removed.

use std::io::ErrorKind;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};

use super::*;

fn mode(path: &std::path::Path) -> u32 {
	std::fs::symlink_metadata(path)
		.expect("metadata")
		.permissions()
		.mode()
		& 0o777
}

#[tokio::test]
async fn bind_creates_a_private_directory_and_a_private_socket() {
	let dir = tempfile::tempdir().expect("tempdir");
	let socket = dir.path().join("signer").join("dkim.sock");
	let _listener = bind(&socket).expect("bind");
	assert_eq!(mode(&dir.path().join("signer")), 0o700);
	assert_eq!(mode(&socket), 0o600);
	assert!(
		std::fs::symlink_metadata(&socket)
			.expect("meta")
			.file_type()
			.is_socket()
	);
}

#[tokio::test]
async fn a_directory_open_to_others_is_refused_until_it_is_closed() {
	let dir = tempfile::tempdir().expect("tempdir");
	let holder = dir.path().join("signer");
	std::fs::create_dir(&holder).expect("mkdir");
	let socket = holder.join("dkim.sock");
	for open in [0o750, 0o705, 0o770, 0o777] {
		std::fs::set_permissions(&holder, std::fs::Permissions::from_mode(open)).expect("chmod");
		let error = bind(&socket).expect_err("refused");
		assert_eq!(error.kind(), ErrorKind::PermissionDenied, "{open:o}");
		assert!(error.to_string().contains("0700"), "{error}");
		assert!(!socket.exists(), "nothing bound in a {open:o} directory");
	}
	std::fs::set_permissions(&holder, std::fs::Permissions::from_mode(0o700)).expect("chmod");
	bind(&socket).expect("a 0700 directory is taken");
}

#[tokio::test]
async fn a_symlinked_directory_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let real = dir.path().join("real");
	std::fs::create_dir(&real).expect("mkdir");
	std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).expect("chmod");
	let link = dir.path().join("link");
	std::os::unix::fs::symlink(&real, &link).expect("symlink");
	let error = bind(&link.join("dkim.sock")).expect_err("refused");
	assert_eq!(error.kind(), ErrorKind::InvalidInput);
	bind(&real.join("dkim.sock")).expect("the real directory is taken");
}

#[tokio::test]
async fn a_stale_socket_is_replaced_and_anything_else_is_left_alone() {
	let dir = tempfile::tempdir().expect("tempdir");
	let socket = dir.path().join("signer").join("dkim.sock");
	drop(bind(&socket).expect("first bind"));
	assert!(socket.exists(), "the first run left its socket");
	drop(bind(&socket).expect("a stale socket is replaced"));

	std::fs::remove_file(&socket).expect("remove");
	std::fs::write(&socket, b"not a socket").expect("write");
	let error = bind(&socket).expect_err("refused");
	assert_eq!(error.kind(), ErrorKind::AlreadyExists);
	assert_eq!(std::fs::read(&socket).expect("read"), b"not a socket");
}

#[tokio::test]
async fn a_path_without_a_directory_is_refused() {
	let error = bind(std::path::Path::new("dkim.sock")).expect_err("refused");
	assert_eq!(error.kind(), ErrorKind::InvalidInput);
}
