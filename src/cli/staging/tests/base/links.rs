//! Links, special files and the size bound are refused before anything is copied.

use super::*;

#[test]
fn symbolic_links_are_never_followed() {
	let (home, source) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
	let target = source.path().join("shadow");
	write(&target, "root secret", 0o600);
	let link = source.path().join("pw");
	std::os::unix::fs::symlink(&target, &link).unwrap();
	let message = refused(
		&imap(&["--password-file", link.to_str().unwrap()]),
		home.path(),
		table::STAGED,
	);
	assert!(
		message.contains("is a symbolic link; links are not followed"),
		"{message}"
	);

	let maildir = source.path().join("Maildir");
	write(&maildir.join("cur/1:2,"), "mail", 0o600);
	std::os::unix::fs::symlink(&target, maildir.join("cur/2:2,")).unwrap();
	let line = os(&[
		"import",
		"--account",
		"a",
		"--maildir",
		maildir.to_str().unwrap(),
	]);
	let message = refused(&line, home.path(), table::STAGED);
	assert!(
		message.contains("2:2,") && message.contains("is a symbolic link; links are not followed"),
		"{message}"
	);
}

#[test]
fn special_files_are_refused() {
	let (home, source) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
	let socket = source.path().join("pw.sock");
	let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
	let message = refused(
		&imap(&["--password-file", socket.to_str().unwrap()]),
		home.path(),
		table::STAGED,
	);
	assert!(message.contains("not a regular file"), "{message}");

	let maildir = source.path().join("Maildir");
	write(&maildir.join("cur/1:2,"), "mail", 0o600);
	let _inside = std::os::unix::net::UnixListener::bind(maildir.join("cur/sock")).unwrap();
	let line = os(&[
		"import",
		"--account",
		"a",
		"--maildir",
		maildir.to_str().unwrap(),
	]);
	let message = refused(&line, home.path(), table::STAGED);
	assert!(
		message.contains("sock") && message.contains("not a regular file"),
		"{message}"
	);
}

#[test]
fn the_size_bound_stops_a_copy() {
	let (home, source) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
	let small = [
		Staged {
			command: &["migrate", "imap"],
			arg: "password_file",
			kind: Kind::ReadFile {
				limit: 8,
				secret: true,
			},
		},
		Staged {
			command: &["import"],
			arg: "maildir",
			kind: Kind::ReadDir { limit: 10 },
		},
	];
	let file = source.path().join("pw");
	write(&file, "12345678", 0o600);
	let line = imap(&["--password-file", file.to_str().unwrap()]);
	Stage::prepare_with(&line, home.path(), me(), &Owner::default().chown(), &small)
		.expect("a file at the bound is copied");
	write(&file, "123456789", 0o600);
	let message = refused(&line, home.path(), &small);
	assert!(message.contains("larger than the 8 bytes"), "{message}");

	let maildir = source.path().join("Maildir");
	write(&maildir.join("cur/1"), "123456", 0o600);
	write(&maildir.join("new/2"), "123456", 0o600);
	let line = os(&[
		"import",
		"--account",
		"a",
		"--maildir",
		maildir.to_str().unwrap(),
	]);
	let message = refused(&line, home.path(), &small);
	assert!(
		message.contains("larger than the 10 bytes"),
		"the bound is the tree's total: {message}"
	);
}
