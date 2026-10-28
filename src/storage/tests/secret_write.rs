use std::os::unix::fs::PermissionsExt;

#[test]
fn write_secret_is_owner_only() {
	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path().join("creds.toml");
	super::write_secret(&path, b"totp_secret = \"JBSWY3DPEHPK3PXP\"").expect("write");
	let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
	assert_eq!(
		mode & 0o777,
		0o600,
		"secret file must be 0600, got {:o}",
		mode & 0o777
	);
	assert_eq!(
		std::fs::read(&path).expect("read"),
		b"totp_secret = \"JBSWY3DPEHPK3PXP\""
	);
}
