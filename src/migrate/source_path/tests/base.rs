//! A path read from another server's configuration stays inside its directory.

use super::super::inside;

#[test]
fn a_relative_name_inside_the_directory_is_accepted() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir(dir.path().join("keys")).expect("keys");
	std::fs::write(dir.path().join("keys").join("dkim.pem"), b"pem").expect("key");
	let path = inside(dir.path(), "PrivateKeyFile", "keys/dkim.pem").expect("inside");
	assert_eq!(std::fs::read(path).expect("read"), b"pem");
}

#[test]
fn an_absolute_name_and_a_climbing_name_are_refused_by_the_setting() {
	let dir = tempfile::tempdir().expect("tempdir");
	for value in [
		"/etc/passwd",
		"../outside.pem",
		"keys/../../outside.pem",
		"",
		"keys/../keys/a.pem",
	] {
		let error = inside(dir.path(), "PrivateKeyFile", value).expect_err(value);
		assert!(error.starts_with("PrivateKeyFile"), "{value}: {error}");
		assert!(
			!error.contains("/etc/passwd"),
			"the refusal does not repeat the path: {error}"
		);
	}
}

#[test]
fn a_link_that_points_outside_the_directory_is_refused() {
	let outer = tempfile::tempdir().expect("tempdir");
	let inner = outer.path().join("config");
	std::fs::create_dir(&inner).expect("config");
	std::fs::write(outer.path().join("secret.pem"), b"secret").expect("secret");
	std::os::unix::fs::symlink(outer.path().join("secret.pem"), inner.join("link.pem"))
		.expect("link");
	assert!(inside(&inner, "private-key", "link.pem").is_err());
}
